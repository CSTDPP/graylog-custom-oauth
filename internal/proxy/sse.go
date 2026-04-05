package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/CSTDPP/graylog-auth-proxy/internal/observability"
)

// SSEHandler proxies Server-Sent Event and MCP streaming connections to the
// Graylog backend. It disables buffering and flushes each chunk as it arrives
// to maintain real-time streaming semantics.
type SSEHandler struct {
	targetURL *url.URL
	transport http.RoundTripper
	metrics   *observability.Metrics
	logger    *slog.Logger
}

// NewSSEHandler creates an SSEHandler that forwards streaming requests to
// targetURL using the provided transport.
func NewSSEHandler(targetURL *url.URL, transport http.RoundTripper, metrics *observability.Metrics) *SSEHandler {
	return &SSEHandler{
		targetURL: targetURL,
		transport: transport,
		metrics:   metrics,
		logger:    slog.Default(),
	}
}

// ServeHTTP proxies an SSE request to the upstream backend, streaming the
// response back to the client with per-chunk flushing. The connection is tied
// to the client's context and terminates when the client disconnects.
func (s *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.metrics.SSEConnectionsActive.Inc()
	defer s.metrics.SSEConnectionsActive.Dec()

	// Clone the request and retarget to the upstream.
	upstreamURL := *r.URL
	upstreamURL.Scheme = s.targetURL.Scheme
	upstreamURL.Host = s.targetURL.Host

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to create upstream SSE request",
			slog.String("error", err.Error()))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request.
	for key, values := range r.Header {
		for _, v := range values {
			upstreamReq.Header.Add(key, v)
		}
	}
	upstreamReq.Header.Set("X-Accel-Buffering", "no")

	resp, err := s.transport.RoundTrip(upstreamReq)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "upstream SSE request failed",
			slog.String("error", err.Error()))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set response headers for SSE streaming.
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the response body with flushing.
	flusher, hasFlusher := w.(http.Flusher)

	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				s.logger.DebugContext(r.Context(), "SSE client write failed",
					slog.String("error", writeErr.Error()))
				return
			}
			if hasFlusher {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				s.logger.DebugContext(r.Context(), "SSE upstream read ended",
					slog.String("error", readErr.Error()))
			}
			return
		}
	}
}

// IsSSERequest reports whether the given request should be handled as an SSE
// stream. A request is considered SSE if its path starts with /api/mcp/ or its
// Accept header contains text/event-stream.
func IsSSERequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/mcp/") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}
