package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/CSTDPP/graylog-auth-proxy/internal/graylog"
	"github.com/CSTDPP/graylog-auth-proxy/internal/observability"
	"github.com/CSTDPP/graylog-auth-proxy/internal/provision"
	"github.com/CSTDPP/graylog-auth-proxy/internal/roles"
	"github.com/CSTDPP/graylog-auth-proxy/internal/session"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGraylogClient implements provision.GraylogClient for handler tests.
type mockGraylogClient struct {
	getUser         func(ctx context.Context, username string) (*graylog.User, error)
	createUser      func(ctx context.Context, req *graylog.CreateUserRequest) error
	updateUserRoles func(ctx context.Context, username string, roles []string) error
}

func (m *mockGraylogClient) GetUser(ctx context.Context, username string) (*graylog.User, error) {
	return m.getUser(ctx, username)
}

func (m *mockGraylogClient) CreateUser(ctx context.Context, req *graylog.CreateUserRequest) error {
	return m.createUser(ctx, req)
}

func (m *mockGraylogClient) UpdateUserRoles(ctx context.Context, username string, rs []string) error {
	return m.updateUserRoles(ctx, username, rs)
}

// testKey is a 32-byte key for session encryption in tests.
var testKey = []byte("0123456789abcdef0123456789abcdef")

// setupHandler creates a Handler wired to a backend httptest.Server and a
// session.Manager suitable for unit testing.
func setupHandler(t *testing.T, mock *mockGraylogClient) (*Handler, *session.Manager, *httptest.Server) {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo X-Remote-User back as a header so tests can inspect it.
		if v := r.Header.Get("X-Remote-User"); v != "" {
			w.Header().Set("X-Received-Remote-User", v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "backend OK")
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	mgr := session.NewManager(testKey, 1*time.Hour)
	mapper := roles.NewMapper(map[string]string{}, "Reader")
	prov := provision.NewProvisioner(mock)
	metrics := observability.NewMetrics(prometheus.NewRegistry())

	handler := NewHandler(backendURL, mgr, prov, mapper, metrics, nil)
	return handler, mgr, backend
}

// setSessionCookie uses the Manager to encode a session and returns the cookie
// so it can be attached to test requests.
func setSessionCookie(t *testing.T, mgr *session.Manager, sess *session.Session) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	require.NoError(t, mgr.Set(rec, sess))
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies, "session cookie should be set")
	return cookies[0]
}

// newTestSession returns a Session suitable for testing.
func newTestSession(username string) *session.Session {
	return &session.Session{
		Username:  username,
		Email:     username + "@example.com",
		Name:      username,
		Roles:     []string{"Reader"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// successMock returns a mock where all operations succeed.
func successMock() *mockGraylogClient {
	return &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return &graylog.User{Username: "test"}, nil
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			return nil
		},
	}
}

func TestServeHTTP_NoSession_Redirects(t *testing.T) {
	handler, _, _ := setupHandler(t, successMock())

	req := httptest.NewRequest(http.MethodGet, "/some/path", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	loc := rec.Header().Get("Location")
	assert.Contains(t, loc, "/oauth/login")
}

func TestServeHTTP_ValidSession_ProxiesToBackend(t *testing.T) {
	handler, mgr, _ := setupHandler(t, successMock())

	sess := newTestSession("alice")
	cookie := setSessionCookie(t, mgr, sess)

	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "backend OK")
}

func TestServeHTTP_ValidSession_InjectsXRemoteUser(t *testing.T) {
	handler, mgr, _ := setupHandler(t, successMock())

	sess := newTestSession("alice")
	cookie := setSessionCookie(t, mgr, sess)

	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "alice", rec.Header().Get("X-Received-Remote-User"))
}

func TestServeHTTP_SpoofedHeaderStripped(t *testing.T) {
	handler, mgr, _ := setupHandler(t, successMock())

	sess := newTestSession("alice")
	cookie := setSessionCookie(t, mgr, sess)

	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	req.AddCookie(cookie)
	req.Header.Set("X-Remote-User", "evil")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// The backend echoes back the X-Remote-User it received.
	assert.Equal(t, "alice", rec.Header().Get("X-Received-Remote-User"),
		"spoofed header should be replaced with session username")
}

func TestServeHTTP_ProvisionError_Returns503(t *testing.T) {
	failMock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return nil, errors.New("graylog unreachable")
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			return nil
		},
	}

	handler, mgr, _ := setupHandler(t, failMock)

	sess := newTestSession("alice")
	cookie := setSessionCookie(t, mgr, sess)

	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
