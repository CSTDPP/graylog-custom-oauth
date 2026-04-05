package session

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

const cookieName = "graylog_session"

// Session holds the authenticated user state stored in an encrypted cookie.
type Session struct {
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Roles     []string  `json:"roles"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Manager handles secure cookie-based session creation, retrieval, and removal.
type Manager struct {
	codec  *securecookie.SecureCookie
	maxAge time.Duration
}

// NewManager creates a Manager. The key must be exactly 32 bytes: the first 16
// bytes are used as the HMAC key and the full 32 bytes as the AES-256
// encryption key.
func NewManager(key []byte, maxAge time.Duration) *Manager {
	// First 16 bytes for HMAC signing, full 32 bytes for AES encryption.
	hashKey := key[:16]
	blockKey := key

	codec := securecookie.New(hashKey, blockKey)
	codec.MaxAge(0) // We handle expiry ourselves via ExpiresAt.

	return &Manager{
		codec:  codec,
		maxAge: maxAge,
	}
}

// Get reads and decodes the session cookie from the request. It returns an
// error if the cookie is missing, cannot be decoded, or has expired.
func (m *Manager) Get(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie not found: %w", err)
	}

	var s Session
	if err := m.codec.Decode(cookieName, cookie.Value, &s); err != nil {
		return nil, fmt.Errorf("failed to decode session cookie: %w", err)
	}

	if time.Now().After(s.ExpiresAt) {
		return nil, errors.New("session has expired")
	}

	return &s, nil
}

// Set encodes the session and writes it as a secure cookie on the response.
func (m *Manager) Set(w http.ResponseWriter, session *Session) error {
	encoded, err := m.codec.Encode(cookieName, session)
	if err != nil {
		return fmt.Errorf("failed to encode session cookie: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.maxAge.Seconds()),
	})

	return nil
}

// Clear removes the session cookie by setting it to an empty value with an
// immediate expiry.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
