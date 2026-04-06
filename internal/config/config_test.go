package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validSessionKey is 64 hex chars encoding 32 bytes.
const validSessionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// setRequiredEnv sets all required environment variables using t.Setenv so
// they are automatically cleaned up after the test.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENTRA_TENANT_ID", "tenant-123")
	t.Setenv("ENTRA_CLIENT_ID", "client-456")
	t.Setenv("ENTRA_CLIENT_SECRET", "secret-789")
	t.Setenv("ENTRA_REDIRECT_URL", "https://example.com/callback")
	t.Setenv("GRAYLOG_URL", "https://graylog.example.com")
	t.Setenv("GRAYLOG_SERVICE_TOKEN", "svc-token-abc")
	t.Setenv("TLS_CERT_FILE", "/etc/tls/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/etc/tls/key.pem")
	t.Setenv("SESSION_KEY", validSessionKey)
	t.Setenv("ROLE_MAP", `{"graylog-admin":"Admin","graylog-reader":"Reader"}`)
}

func TestLoad_ValidConfig(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "tenant-123", cfg.EntraTenantID)
	assert.Equal(t, "client-456", cfg.EntraClientID)
	assert.Equal(t, "secret-789", cfg.EntraClientSecret)
	assert.Equal(t, "https://example.com/callback", cfg.EntraRedirectURL)
	assert.Equal(t, "https://graylog.example.com", cfg.GraylogURL)
	assert.Equal(t, "svc-token-abc", cfg.GraylogServiceToken)
	assert.Equal(t, "/etc/tls/cert.pem", cfg.TLSCertFile)
	assert.Equal(t, "/etc/tls/key.pem", cfg.TLSKeyFile)
	assert.Len(t, cfg.SessionKey, 32)
	assert.Equal(t, map[string]string{"graylog-admin": "Admin", "graylog-reader": "Reader"}, cfg.RoleMap)
	assert.Equal(t, "secret", cfg.OIDCMode)
	assert.Equal(t, "X-Remote-User", cfg.RemoteUserHeader)
	assert.Equal(t, []string{"X-Remote-User", "X-Remote-Email", "X-Remote-Name"}, cfg.StripHeaders)
}

func TestLoad_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, ":8443", cfg.ListenAddr)
	assert.Equal(t, "Reader", cfg.DefaultRole)
	assert.Equal(t, 8*time.Hour, cfg.SessionMaxAge)
	assert.Equal(t, "secret", cfg.OIDCMode)
	assert.Equal(t, "X-Remote-User", cfg.RemoteUserHeader)
}

func TestLoad_MissingRequired(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ENTRA_TENANT_ID", "")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENTRA_TENANT_ID")
}

func TestLoad_InvalidSessionKey(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SESSION_KEY", "short")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SESSION_KEY")
}

func TestLoad_InvalidSessionKeyNotHex(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SESSION_KEY", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SESSION_KEY")
}

func TestLoad_InvalidRoleMap(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ROLE_MAP", "not json")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ROLE_MAP")
}

func TestLoad_OptionalGraylogCACert(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("GRAYLOG_CA_CERT_FILE", "/etc/tls/ca.pem")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "/etc/tls/ca.pem", cfg.GraylogCACertFile)
}

func TestLoad_CustomSessionMaxAge(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SESSION_MAX_AGE", "2h")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, cfg.SessionMaxAge)
}

func TestLoad_WorkloadIdentityMode(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("OIDC_MODE", "workloadIdentity")
	t.Setenv("ENTRA_CLIENT_SECRET", "") // not required in workload identity mode

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "workloadIdentity", cfg.OIDCMode)
	assert.Empty(t, cfg.EntraClientSecret)
}

func TestLoad_SecretFromFile(t *testing.T) {
	setRequiredEnv(t)

	// Write a secret to a temp file.
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "client-secret")
	err := os.WriteFile(secretFile, []byte("file-based-secret\n"), 0o600)
	require.NoError(t, err)

	// Use _FILE variant instead of direct env var.
	t.Setenv("ENTRA_CLIENT_SECRET", "")
	t.Setenv("ENTRA_CLIENT_SECRET_FILE", secretFile)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "file-based-secret", cfg.EntraClientSecret)
}

func TestLoad_SessionKeyFromFile(t *testing.T) {
	setRequiredEnv(t)

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "session-key")
	err := os.WriteFile(keyFile, []byte(validSessionKey+"\n"), 0o600)
	require.NoError(t, err)

	t.Setenv("SESSION_KEY", "")
	t.Setenv("SESSION_KEY_FILE", keyFile)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Len(t, cfg.SessionKey, 32)
}

func TestLoad_CustomHeaders(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("REMOTE_USER_HEADER", "X-Forwarded-User")
	t.Setenv("STRIP_HEADERS", "X-Forwarded-User, X-Custom")
	t.Setenv("INJECT_HEADERS", `{"X-Source":"auth-proxy"}`)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "X-Forwarded-User", cfg.RemoteUserHeader)
	assert.Equal(t, []string{"X-Forwarded-User", "X-Custom"}, cfg.StripHeaders)
	assert.Equal(t, map[string]string{"X-Source": "auth-proxy"}, cfg.InjectHeaders)
}
