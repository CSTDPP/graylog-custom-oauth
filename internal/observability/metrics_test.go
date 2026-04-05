package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHealthChecker implements HealthChecker for testing.
type mockHealthChecker struct {
	err error
}

func (m *mockHealthChecker) Healthy(_ context.Context) error {
	return m.err
}

func TestHealthzHandler(t *testing.T) {
	handler := HealthzHandler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestReadyzHandler_Healthy(t *testing.T) {
	checker := &mockHealthChecker{err: nil}
	handler := ReadyzHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestReadyzHandler_Unhealthy(t *testing.T) {
	checker := &mockHealthChecker{err: errors.New("connection refused")}
	handler := ReadyzHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "unavailable")
}

func TestNewMetrics_RegistersWithoutPanic(t *testing.T) {
	reg := prometheus.NewRegistry()

	require.NotPanics(t, func() {
		m := NewMetrics(reg)
		assert.NotNil(t, m)
		assert.NotNil(t, m.RequestsTotal)
		assert.NotNil(t, m.RequestDuration)
		assert.NotNil(t, m.AuthOperationsTotal)
		assert.NotNil(t, m.SSEConnectionsActive)
		assert.NotNil(t, m.GraylogAPITotal)
	})
}
