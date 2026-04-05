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
}

// Load reads configuration from environment variables, validates all required
// fields, and returns a fully populated Config or an error describing what is
// missing or malformed.
func Load() (*Config, error) {
	cfg := &Config{
		EntraTenantID:       os.Getenv("ENTRA_TENANT_ID"),
		EntraClientID:       os.Getenv("ENTRA_CLIENT_ID"),
		EntraClientSecret:   os.Getenv("ENTRA_CLIENT_SECRET"),
		EntraRedirectURL:    os.Getenv("ENTRA_REDIRECT_URL"),
		GraylogURL:          os.Getenv("GRAYLOG_URL"),
		GraylogServiceToken: os.Getenv("GRAYLOG_SERVICE_TOKEN"),
		GraylogCACertFile:   os.Getenv("GRAYLOG_CA_CERT_FILE"),
		ListenAddr:          os.Getenv("LISTEN_ADDR"),
		TLSCertFile:         os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:          os.Getenv("TLS_KEY_FILE"),
		DefaultRole:         os.Getenv("DEFAULT_ROLE"),
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = "Reader"
	}

	var errs []string

	// Validate required string fields.
	required := map[string]string{
		"ENTRA_TENANT_ID":       cfg.EntraTenantID,
		"ENTRA_CLIENT_ID":       cfg.EntraClientID,
		"ENTRA_CLIENT_SECRET":   cfg.EntraClientSecret,
		"ENTRA_REDIRECT_URL":    cfg.EntraRedirectURL,
		"GRAYLOG_URL":           cfg.GraylogURL,
		"GRAYLOG_SERVICE_TOKEN": cfg.GraylogServiceToken,
		"TLS_CERT_FILE":         cfg.TLSCertFile,
		"TLS_KEY_FILE":          cfg.TLSKeyFile,
	}
	for name, val := range required {
		if val == "" {
			errs = append(errs, fmt.Sprintf("required environment variable %s is not set", name))
		}
	}

	// Parse SESSION_KEY from hex.
	sessionKeyHex := os.Getenv("SESSION_KEY")
	if sessionKeyHex == "" { //nolint:gocritic // ifElseChain: validation logic reads better as if/else
		errs = append(errs, "required environment variable SESSION_KEY is not set")
	} else {
		decoded, err := hex.DecodeString(sessionKeyHex)
		if err != nil { //nolint:gocritic // ifElseChain: validation chain is clearer than switch
			errs = append(errs, fmt.Sprintf("SESSION_KEY is not valid hex: %v", err))
		} else if len(decoded) != 32 {
			errs = append(errs, fmt.Sprintf("SESSION_KEY must be exactly 32 bytes (64 hex chars), got %d bytes", len(decoded)))
		} else {
			cfg.SessionKey = decoded
		}
	}

	// Parse ROLE_MAP from JSON.
	roleMapJSON := os.Getenv("ROLE_MAP")
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

	// Parse SESSION_MAX_AGE with a default of 8 hours.
	cfg.SessionMaxAge = 8 * time.Hour
	if maxAgeStr := os.Getenv("SESSION_MAX_AGE"); maxAgeStr != "" {
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
