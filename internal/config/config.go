// Package config loads and validates application configuration from environment variables.
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	EntraTenantID     string
	EntraClientID     string
	EntraClientSecret string
	EntraRedirectURL  string
	OIDCMode          string // "secret" (default) or "workloadIdentity"

	GraylogURL          string
	GraylogServiceToken string
	GraylogCACertFile   string // optional, for custom CA

	ListenAddr  string // default ":8443"
	TLSCertFile string
	TLSKeyFile  string

	SessionKey    []byte            // 32 bytes, parsed from hex env var
	RoleMap       map[string]string // parsed from JSON env var ROLE_MAP
	DefaultRole   string            // default "Reader"
	SessionMaxAge time.Duration     // default 8h

	// Header configuration
	RemoteUserHeader string   // default "X-Remote-User"
	StripHeaders     []string // default ["X-Remote-User", "X-Remote-Email", "X-Remote-Name"]
	InjectHeaders    map[string]string
}

// Load reads configuration from environment variables, validates all required
// fields, and returns a fully populated Config or an error describing what is
// missing or malformed.
//
// For sensitive values, Load supports a _FILE suffix convention: if FOO_FILE is
// set, the value is read from the file at that path instead of from FOO. This
// allows mounting Kubernetes Secrets as volumes.
func Load() (*Config, error) {
	cfg := &Config{
		EntraTenantID:       getEnv("ENTRA_TENANT_ID"),
		EntraClientID:       getEnv("ENTRA_CLIENT_ID"),
		EntraClientSecret:   getEnvOrFile("ENTRA_CLIENT_SECRET"),
		EntraRedirectURL:    getEnv("ENTRA_REDIRECT_URL"),
		OIDCMode:            getEnv("OIDC_MODE"),
		GraylogURL:          getEnv("GRAYLOG_URL"),
		GraylogServiceToken: getEnvOrFile("GRAYLOG_SERVICE_TOKEN"),
		GraylogCACertFile:   getEnv("GRAYLOG_CA_CERT_FILE"),
		ListenAddr:          getEnv("LISTEN_ADDR"),
		TLSCertFile:         getEnv("TLS_CERT_FILE"),
		TLSKeyFile:          getEnv("TLS_KEY_FILE"),
		DefaultRole:         getEnv("DEFAULT_ROLE"),
		RemoteUserHeader:    getEnv("REMOTE_USER_HEADER"),
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = "Reader"
	}
	if cfg.OIDCMode == "" {
		cfg.OIDCMode = "secret"
	}
	if cfg.RemoteUserHeader == "" {
		cfg.RemoteUserHeader = "X-Remote-User"
	}

	var errs []string

	// Validate required string fields.
	required := map[string]string{
		"ENTRA_TENANT_ID":    cfg.EntraTenantID,
		"ENTRA_CLIENT_ID":    cfg.EntraClientID,
		"ENTRA_REDIRECT_URL": cfg.EntraRedirectURL,
		"GRAYLOG_URL":        cfg.GraylogURL,
		"TLS_CERT_FILE":      cfg.TLSCertFile,
		"TLS_KEY_FILE":       cfg.TLSKeyFile,
	}

	// ENTRA_CLIENT_SECRET is only required in "secret" mode.
	if cfg.OIDCMode == "secret" {
		required["ENTRA_CLIENT_SECRET"] = cfg.EntraClientSecret
	}

	// GRAYLOG_SERVICE_TOKEN is always required.
	required["GRAYLOG_SERVICE_TOKEN"] = cfg.GraylogServiceToken

	for name, val := range required {
		if val == "" {
			errs = append(errs, fmt.Sprintf("required environment variable %s is not set", name))
		}
	}

	// Parse SESSION_KEY from hex (supports _FILE).
	sessionKeyHex := getEnvOrFile("SESSION_KEY")
	if sessionKeyHex == "" { //nolint:gocritic // ifElseChain: validation logic reads better as if/else
		errs = append(errs, "required environment variable SESSION_KEY is not set")
	} else {
		decoded, err := hex.DecodeString(strings.TrimSpace(sessionKeyHex))
		if err != nil { //nolint:gocritic // ifElseChain: validation chain is clearer than switch
			errs = append(errs, fmt.Sprintf("SESSION_KEY is not valid hex: %v", err))
		} else if len(decoded) != 32 {
			errs = append(errs, fmt.Sprintf("SESSION_KEY must be exactly 32 bytes (64 hex chars), got %d bytes", len(decoded)))
		} else {
			cfg.SessionKey = decoded
		}
	}

	// Parse ROLE_MAP from JSON (supports _FILE).
	roleMapJSON := getEnvOrFile("ROLE_MAP")
	if roleMapJSON == "" {
		errs = append(errs, "required environment variable ROLE_MAP is not set")
	} else {
		roleMap := make(map[string]string)
		if err := json.Unmarshal([]byte(roleMapJSON), &roleMap); err != nil {
			errs = append(errs, fmt.Sprintf("ROLE_MAP is not valid JSON: %v", err))
		} else {
			cfg.RoleMap = roleMap
		}
	}

	// Parse STRIP_HEADERS (comma-separated).
	if stripStr := getEnv("STRIP_HEADERS"); stripStr != "" {
		cfg.StripHeaders = strings.Split(stripStr, ",")
		for i := range cfg.StripHeaders {
			cfg.StripHeaders[i] = strings.TrimSpace(cfg.StripHeaders[i])
		}
	} else {
		cfg.StripHeaders = []string{"X-Remote-User", "X-Remote-Email", "X-Remote-Name"}
	}

	// Parse INJECT_HEADERS (JSON object).
	if injectStr := getEnv("INJECT_HEADERS"); injectStr != "" {
		inject := make(map[string]string)
		if err := json.Unmarshal([]byte(injectStr), &inject); err != nil {
			errs = append(errs, fmt.Sprintf("INJECT_HEADERS is not valid JSON: %v", err))
		} else {
			cfg.InjectHeaders = inject
		}
	}

	// Parse SESSION_MAX_AGE with a default of 8 hours.
	cfg.SessionMaxAge = 8 * time.Hour
	if maxAgeStr := getEnv("SESSION_MAX_AGE"); maxAgeStr != "" {
		d, err := time.ParseDuration(maxAgeStr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("SESSION_MAX_AGE is not a valid duration: %v", err))
		} else {
			cfg.SessionMaxAge = d
		}
	}

	if len(errs) > 0 {
		return nil, errors.New("configuration errors:\n  " + strings.Join(errs, "\n  "))
	}

	return cfg, nil
}

// getEnv reads an environment variable.
func getEnv(name string) string {
	return os.Getenv(name)
}

// getEnvOrFile reads a value from the environment variable NAME, or if
// NAME_FILE is set, reads the value from the file at that path. The _FILE
// variant takes precedence when both are set.
func getEnvOrFile(name string) string {
	if filePath := os.Getenv(name + "_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath) // #nosec G304 G703 //nolint:gosec -- file path from env var, not user input
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return os.Getenv(name)
}
