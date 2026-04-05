package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/CSTDPP/graylog-auth-proxy/internal/config"
	"github.com/CSTDPP/graylog-auth-proxy/internal/graylog"
	"github.com/CSTDPP/graylog-auth-proxy/internal/jwt"
	"github.com/CSTDPP/graylog-auth-proxy/internal/observability"
	"github.com/CSTDPP/graylog-auth-proxy/internal/oidc"
	"github.com/CSTDPP/graylog-auth-proxy/internal/provision"
	"github.com/CSTDPP/graylog-auth-proxy/internal/proxy"
	"github.com/CSTDPP/graylog-auth-proxy/internal/roles"
	"github.com/CSTDPP/graylog-auth-proxy/internal/session"
)

var version = "dev" // set by ldflags at build time

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration from environment variables.
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("starting graylog-auth-proxy",
		"version", version,
		"listen_addr", cfg.ListenAddr,
		"graylog_url", cfg.GraylogURL,
		"tenant_id", cfg.EntraTenantID,
		"client_id", cfg.EntraClientID,
		"redirect_url", cfg.EntraRedirectURL,
		"default_role", cfg.DefaultRole,
		"session_max_age", cfg.SessionMaxAge.String(),
		"client_secret", "REDACTED",
		"service_token", "REDACTED",
		"session_key", "REDACTED",
	)

	// Create JWT validator.
	ctx := context.Background()
	validator, err := jwt.NewValidator(ctx, cfg.EntraTenantID, cfg.EntraClientID)
	if err != nil {
		logger.Error("failed to create JWT validator", "error", err)
		os.Exit(1)
	}

	// Create session manager.
	sessions := session.NewManager(cfg.SessionKey, cfg.SessionMaxAge)

	// Create OIDC handler.
	oidcHandler, err := oidc.NewHandler(ctx, cfg, validator, sessions, logger)
	if err != nil {
		logger.Error("failed to create OIDC handler", "error", err)
		os.Exit(1)
	}

	// Create role mapper.
	roleMapper := roles.NewMapper(cfg.RoleMap, cfg.DefaultRole)

	// Create Graylog API client.
	graylogClient, err := graylog.NewClient(cfg.GraylogURL, cfg.GraylogServiceToken, cfg.GraylogCACertFile, logger)
	if err != nil {
		logger.Error("failed to create Graylog client", "error", err)
		os.Exit(1)
	}

	// Create user provisioner.
	provisioner := provision.NewProvisioner(graylogClient)

	// Set up Prometheus metrics.
	registry := prometheus.NewRegistry()
	metrics := observability.NewMetrics(registry)

	// Parse Graylog URL and build TLS config for the reverse proxy backend.
	graylogURL, err := url.Parse(cfg.GraylogURL)
	if err != nil {
		logger.Error("failed to parse Graylog URL", "error", err)
		os.Exit(1)
	}

	var backendTLSConfig *tls.Config
	if cfg.GraylogCACertFile != "" {
		caCert, err := os.ReadFile(cfg.GraylogCACertFile)
		if err != nil {
			logger.Error("failed to read Graylog CA certificate file", "error", err, "path", cfg.GraylogCACertFile)
			os.Exit(1)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			logger.Error("failed to parse Graylog CA certificate", "path", cfg.GraylogCACertFile)
			os.Exit(1)
		}
		backendTLSConfig = &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		}
	}

	// Create reverse proxy handler.
	proxyHandler := proxy.NewHandler(graylogURL, sessions, provisioner, roleMapper, metrics, backendTLSConfig)

	// Set up HTTP routes.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/login", oidcHandler.HandleLogin)
	mux.HandleFunc("GET /oauth/callback", oidcHandler.HandleCallback)
	mux.HandleFunc("GET /oauth/logout", oidcHandler.HandleLogout)
	mux.HandleFunc("GET /healthz", observability.HealthzHandler())
	mux.HandleFunc("GET /readyz", observability.ReadyzHandler(graylogClient))
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.Handle("/", proxyHandler)

	// Load TLS certificate and key for the server.
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		logger.Error("failed to load TLS certificate", "error", err, "cert", cfg.TLSCertFile, "key", cfg.TLSKeyFile)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:               cfg.ListenAddr,
		Handler:            mux,
		TLSConfig:          tlsConfig,
		ReadHeaderTimeout:  10 * time.Second,
	}

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening", "addr", cfg.ListenAddr)
		// TLS is configured via TLSConfig, so use ListenAndServeTLS with empty
		// cert/key paths since the certificate is already loaded.
		errCh <- server.ListenAndServeTLS("", "")
	}()

	// Wait for shutdown signal or server error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown with timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	if err := server.Shutdown(shutdownCtx); err != nil {
		cancel()
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	cancel()
	logger.Info("server stopped")
}
