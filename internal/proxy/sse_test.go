package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CSTDPP/graylog-auth-proxy/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestIsSSERequest_MCPPath(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/mcp/sse", nil)
	assert.True(t, IsSSERequest(r))
}

func TestIsSSERequest_MCPSubpath(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/mcp/foo/bar", nil)
	assert.True(t, IsSSERequest(r))
}

func TestIsSSERequest_AcceptHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	r.Header.Set("Accept", "text/event-stream")
	assert.True(t, IsSSERequest(r))
}

func TestIsSSERequest_NormalRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("Accept", "application/json")
	assert.False(t, IsSSERequest(r))
}

func TestIsSSERequest_EmptyPath(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, IsSSERequest(r))
}

func TestSSEHandler_StreamsData(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: hello\n\n")
	}))
	defer backend.Close()

	targetURL, err := url.Parse(backend.URL)
	assert.NoError(t, err)

	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	handler := NewSSEHandler(targetURL, http.DefaultTransport, metrics)

	req := httptest.NewRequest(http.MethodGet, "/api/mcp/sse", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "data: hello")
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

func TestSSEHandler_ContextCancellation(t *testing.T) {
	// Backend that blocks until context is done.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block until the request context is cancelled.
		<-r.Context().Done()
	}))
	defer backend.Close()

	targetURL, err := url.Parse(backend.URL)
	assert.NoError(t, err)

	reg := prometheus.NewRegistry()
	metrics := observability.NewMetrics(reg)

	handler := NewSSEHandler(targetURL, http.DefaultTransport, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/mcp/sse", nil).WithContext(ctx)

	// Use a pipe-based ResponseWriter so flushing works and the handler can
	// detect a closed client connection.
	pr, pw := io.Pipe()
	defer pr.Close()

	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()

	// Cancel the context to simulate client disconnect.
	cancel()
	_ = pw.Close()

	select {
	case <-done:
		// Handler returned — success.
	case <-time.After(5 * time.Second):
		t.Fatal("SSEHandler did not return after context cancellation")
	}

	_ = strings.NewReader("") // keep strings import used
}
