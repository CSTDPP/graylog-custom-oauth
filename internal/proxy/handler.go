// Package proxy provides the authentication middleware and reverse proxy handlers.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/CSTDPP/graylog-auth-proxy/internal/observability"
	"github.com/CSTDPP/graylog-auth-proxy/internal/provision"
	"github.com/CSTDPP/graylog-auth-proxy/internal/roles"
	"github.com/CSTDPP/graylog-auth-proxy/internal/session"
)

const (
	loginPath        = "/oauth/login"
	provisionTimeout = 5 * time.Second
)

// HeaderConfig controls which headers are stripped, injected, and used for
// the authenticated username.
type HeaderConfig struct {
	RemoteUserHeader string
	StripHeaders     []string
	InjectHeaders    map[string]string
}

// Handler is the main HTTP handler that authenticates requests via session
// cookies, provisions users in Graylog, and proxies traffic to the Graylog
// backend.
type Handler struct {
	sessions    *session.Manager
	provisioner *provision.Provisioner
	roleMapper  *roles.Mapper
	metrics     *observability.Metrics
	proxy       *httputil.ReverseProxy
	sseHandler  *SSEHandler
	headers     HeaderConfig
	loginPath   string
	logger      *slog.Logger
}

// NewHandler creates a Handler that proxies authenticated requests to
// targetURL. The provided tlsConfig is used for the backend connection to
// Graylog.
func NewHandler(
	targetURL *url.URL,
	sessions *session.Manager,
	provisioner *provision.Provisioner,
	roleMapper *roles.Mapper,
	metrics *observability.Metrics,
	tlsConfig *tls.Config,
	headers HeaderConfig,
) *Handler {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host
		},
		Transport: transport,
	}

	sseHandler := NewSSEHandler(targetURL, transport, metrics)

	return &Handler{
		sessions:    sessions,
		provisioner: provisioner,
		roleMapper:  roleMapper,
		metrics:     metrics,
		proxy:       proxy,
		sseHandler:  sseHandler,
		headers:     headers,
		loginPath:   loginPath,
		logger:      slog.Default(),
	}
}

// ServeHTTP authenticates the request, provisions the user in Graylog, and
// forwards the request to the appropriate backend handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	pathPattern := normalizePathPattern(r.URL.Path)

	// 1. Check session.
	sess, err := h.sessions.Get(r)
	if err != nil {
		h.metrics.AuthOperationsTotal.WithLabelValues("session_check", "missing").Inc()
		redirectURL := fmt.Sprintf("%s?redirect=%s", h.loginPath, url.QueryEscape(r.RequestURI))
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	h.metrics.AuthOperationsTotal.WithLabelValues("session_check", "valid").Inc()

	// 2. Strip configured headers to prevent spoofing.
	for _, header := range h.headers.StripHeaders {
		r.Header.Del(header)
	}

	// 3. Inject the authenticated identity header.
	r.Header.Set(h.headers.RemoteUserHeader, sess.Username)

	// 4. Inject any additional configured headers.
	for k, v := range h.headers.InjectHeaders {
		r.Header.Set(k, v)
	}

	// 5. Provision user in Graylog with a bounded timeout.
	provCtx, provCancel := context.WithTimeout(r.Context(), provisionTimeout)
	defer provCancel()

	info := provision.UserInfo{
		Username: sess.Username,
		Email:    sess.Email,
		Name:     sess.Name,
		Roles:    sess.Roles,
	}

	if provErr := h.provisioner.Provision(provCtx, info); provErr != nil {
		h.logger.ErrorContext(r.Context(), "user provisioning failed",
			slog.String("username", sess.Username),
			slog.String("error", provErr.Error()))
		h.metrics.AuthOperationsTotal.WithLabelValues("provision", "error").Inc()
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	h.metrics.AuthOperationsTotal.WithLabelValues("provision", "success").Inc()

	// 6. Delegate to SSE handler or standard reverse proxy.
	recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	if IsSSERequest(r) {
		h.sseHandler.ServeHTTP(recorder, r)
	} else {
		h.proxy.ServeHTTP(recorder, r)
	}

	// 7. Record request metrics.
	duration := time.Since(start).Seconds()
	statusStr := strconv.Itoa(recorder.statusCode)
	h.metrics.RequestsTotal.WithLabelValues(r.Method, pathPattern, statusStr).Inc()
	h.metrics.RequestDuration.WithLabelValues(r.Method, pathPattern).Observe(duration)
}

// statusRecorder wraps http.ResponseWriter to capture the status code written
// by downstream handlers.
type statusRecorder struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wroteHeader {
		sr.statusCode = code
		sr.wroteHeader = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// normalizePathPattern reduces a URL path to a pattern suitable for use as a
// Prometheus label. It keeps the first two path segments and replaces the rest
// with a wildcard to limit cardinality.
func normalizePathPattern(path string) string {
	if path == "" || path == "/" {
		return "/"
	}

	// Keep up to 2 segments: /api/users/foo -> /api/users/*
	segments := 0
	for i := 1; i < len(path); i++ {
		if path[i] == '/' {
			segments++
			if segments >= 2 {
				return path[:i] + "/*"
			}
		}
	}
	return path
}
