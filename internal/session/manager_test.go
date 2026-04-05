package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey is exactly 32 bytes used across all session tests.
var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestManager() *Manager {
	return NewManager(testKey, 8*time.Hour)
}

func newTestSession() *Session {
	return &Session{
		Username:  "jdoe",
		Email:     "jdoe@example.com",
		Name:      "Jane Doe",
		Roles:     []string{"Admin", "Reader"},
		IssuedAt:  time.Now().Truncate(time.Second),
		ExpiresAt: time.Now().Add(8 * time.Hour).Truncate(time.Second),
	}
}

// setAndExtractCookie calls Set on a recorder and returns the resulting cookie.
func setAndExtractCookie(t *testing.T, mgr *Manager, sess *Session) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	err := mgr.Set(rec, sess)
	require.NoError(t, err)

	resp := rec.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	require.NotEmpty(t, cookies, "expected at least one Set-Cookie header")

	for _, c := range cookies {
		if c.Name == "graylog_session" {
			return c
		}
	}
	t.Fatal("graylog_session cookie not found in response")
	return nil
}

func TestSetGet_Roundtrip(t *testing.T) {
	mgr := newTestManager()
	original := newTestSession()

	cookie := setAndExtractCookie(t, mgr, original)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	got, err := mgr.Get(req)
	require.NoError(t, err)

	assert.Equal(t, original.Username, got.Username)
	assert.Equal(t, original.Email, got.Email)
	assert.Equal(t, original.Name, got.Name)
	assert.Equal(t, original.Roles, got.Roles)
	assert.True(t, original.IssuedAt.Equal(got.IssuedAt), "IssuedAt mismatch")
	assert.True(t, original.ExpiresAt.Equal(got.ExpiresAt), "ExpiresAt mismatch")
}

func TestGet_NoCookie(t *testing.T) {
	mgr := newTestManager()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := mgr.Get(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cookie")
}

func TestGet_ExpiredSession(t *testing.T) {
	mgr := newTestManager()
	sess := newTestSession()
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // expired

	cookie := setAndExtractCookie(t, mgr, sess)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	_, err := mgr.Get(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestGet_TamperedCookie(t *testing.T) {
	mgr := newTestManager()
	sess := newTestSession()

	cookie := setAndExtractCookie(t, mgr, sess)
	// Tamper with the cookie value.
	cookie.Value = cookie.Value[:len(cookie.Value)-4] + "XXXX"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	_, err := mgr.Get(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestClear(t *testing.T) {
	mgr := newTestManager()

	rec := httptest.NewRecorder()
	mgr.Clear(rec)

	resp := rec.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	require.NotEmpty(t, cookies)

	var found bool
	for _, c := range cookies {
		if c.Name == "graylog_session" {
			found = true
			assert.Equal(t, -1, c.MaxAge)
			assert.Empty(t, c.Value)
		}
	}
	assert.True(t, found, "graylog_session cookie not found in Clear response")
}

func TestGet_InvalidCookieValue(t *testing.T) {
	mgr := newTestManager()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "graylog_session",
		Value: "totally-garbage-value!!!",
	})

	_, err := mgr.Get(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}
