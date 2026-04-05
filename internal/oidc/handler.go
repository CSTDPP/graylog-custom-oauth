package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"

	"github.com/CSTDPP/graylog-auth-proxy/internal/config"
	"github.com/CSTDPP/graylog-auth-proxy/internal/jwt"
	"github.com/CSTDPP/graylog-auth-proxy/internal/session"
)

const (
	tempCookieName  = "oauth_state"
	tempCookieMaxAge = 300 // 5 minutes
)

// tempCookieData holds the OAuth state and PKCE verifier stored in a
// short-lived cookie during the authorization flow.
type tempCookieData struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
}

// Handler implements the OAuth 2.0 / OIDC authorization code flow with PKCE
// against Microsoft Entra ID.
type Handler struct {
	oauth2Config oauth2.Config
	provider     *coreoidc.Provider
	validator    *jwt.Validator
	sessions     *session.Manager
	logger       *slog.Logger
	tenantID     string
	redirectURL  string
	tempCodec    *securecookie.SecureCookie
}

// NewHandler creates a Handler configured for the OIDC authorization code flow.
// It fetches the provider discovery document during construction.
func NewHandler(ctx context.Context, cfg *config.Config, validator *jwt.Validator, sessions *session.Manager, logger *slog.Logger) (*Handler, error) {
	providerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.EntraTenantID)

	provider, err := coreoidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.EntraClientID,
		ClientSecret: cfg.EntraClientSecret,
		RedirectURL:  cfg.EntraRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{coreoidc.ScopeOpenID, "profile", "email"},
	}

	// Use the first 16 bytes of the session key for HMAC on the temp cookie.
	// No encryption needed for the temp cookie since it only holds random state.
	tempCodec := securecookie.New(cfg.SessionKey[:16], nil)
	tempCodec.MaxAge(tempCookieMaxAge)

	return &Handler{
		oauth2Config: oauth2Cfg,
		provider:     provider,
		validator:    validator,
		sessions:     sessions,
		logger:       logger,
		tenantID:     cfg.EntraTenantID,
		redirectURL:  cfg.EntraRedirectURL,
		tempCodec:    tempCodec,
	}, nil
}

// HandleLogin starts the OIDC authorization code flow by redirecting the user
// to the Entra authorize endpoint with a crypto-random state and PKCE challenge.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomHex(32)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "failed to generate OAuth state", slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	verifier, err := randomURLSafe(32)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "failed to generate PKCE verifier", slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := tempCookieData{State: state, Verifier: verifier}
	encoded, err := h.tempCodec.Encode(tempCookieName, data)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "failed to encode temp cookie", slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     tempCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   tempCookieMaxAge,
	})

	challenge := pkceS256Challenge(verifier)
	authURL := h.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	h.logger.DebugContext(r.Context(), "redirecting to authorization endpoint",
		slog.String("redirect_url", authURL))

	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback processes the authorization server callback, exchanges the
// auth code for tokens, validates the ID token, creates a session, and
// redirects the user to the application root.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read and validate temp cookie.
	cookie, err := r.Cookie(tempCookieName)
	if err != nil {
		h.logger.WarnContext(ctx, "temp cookie not found", slog.String("error", err.Error()))
		http.Error(w, "missing OAuth state cookie; please restart login", http.StatusBadRequest)
		return
	}

	var data tempCookieData
	if err := h.tempCodec.Decode(tempCookieName, cookie.Value, &data); err != nil {
		h.logger.WarnContext(ctx, "failed to decode temp cookie", slog.String("error", err.Error()))
		http.Error(w, "invalid OAuth state cookie; please restart login", http.StatusBadRequest)
		return
	}

	// Clear temp cookie immediately.
	http.SetCookie(w, &http.Cookie{
		Name:     tempCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Validate state.
	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != data.State {
		h.logger.WarnContext(ctx, "OAuth state mismatch",
			slog.String("expected", data.State),
			slog.String("received", queryState))
		http.Error(w, "invalid OAuth state; possible CSRF attack", http.StatusBadRequest)
		return
	}

	// Check for error from authorization server.
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.logger.ErrorContext(ctx, "authorization server returned error",
			slog.String("error", errCode),
			slog.String("description", errDesc))
		http.Error(w, fmt.Sprintf("authorization failed: %s", errCode), http.StatusForbidden)
		return
	}

	// Exchange auth code for tokens with PKCE verifier.
	code := r.URL.Query().Get("code")
	if code == "" {
		h.logger.WarnContext(ctx, "callback missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := h.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", data.Verifier))
	if err != nil {
		h.logger.ErrorContext(ctx, "token exchange failed", slog.String("error", err.Error()))
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// Extract and validate ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		h.logger.ErrorContext(ctx, "no id_token in token response")
		http.Error(w, "missing ID token", http.StatusInternalServerError)
		return
	}

	claims, err := h.validator.Validate(ctx, rawIDToken)
	if err != nil {
		h.logger.ErrorContext(ctx, "ID token validation failed", slog.String("error", err.Error()))
		http.Error(w, "invalid ID token", http.StatusForbidden)
		return
	}

	h.logger.InfoContext(ctx, "user authenticated",
		slog.String("username", claims.Username),
		slog.String("email", claims.Email))

	// Create session.
	now := time.Now()
	sess := &session.Session{
		Username:  claims.Username,
		Email:     claims.Email,
		Name:      claims.Name,
		Roles:     claims.Roles,
		IssuedAt:  now,
		ExpiresAt: now.Add(8 * time.Hour),
	}

	if err := h.sessions.Set(w, sess); err != nil {
		h.logger.ErrorContext(ctx, "failed to set session", slog.String("error", err.Error()))
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogout clears the session cookie and redirects the user to the Entra
// logout endpoint.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	h.sessions.Clear(w)

	logoutURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
		h.tenantID,
		url.QueryEscape(h.redirectURL),
	)

	h.logger.DebugContext(r.Context(), "redirecting to logout endpoint",
		slog.String("logout_url", logoutURL))

	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// randomHex generates n random bytes and returns them as a hex-encoded string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// randomURLSafe generates n random bytes and returns them as a URL-safe
// base64-encoded string (no padding), suitable for use as a PKCE verifier.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceS256Challenge computes the S256 PKCE challenge for the given verifier.
func pkceS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

