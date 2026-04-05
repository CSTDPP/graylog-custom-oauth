package graylog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

// retryBackoffs defines the wait duration before each retry attempt. The
// initial request has no delay; subsequent retries wait 100ms, 500ms, and 2s.
var retryBackoffs = [3]time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second}

// maxAttempts is the total number of request attempts (1 initial + 3 retries).
const maxAttempts = 4

// User represents a Graylog user as returned by the REST API.
type User struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	FullName string   `json:"full_name"`
	Roles    []string `json:"roles"`
}

// CreateUserRequest is the payload for creating a new Graylog user.
type CreateUserRequest struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	FullName    string   `json:"full_name"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// Client communicates with the Graylog REST API using bearer token
// authentication and optional custom TLS configuration.
type Client struct {
	httpClient   *http.Client
	baseURL      string
	serviceToken string
	logger       *slog.Logger
}

// NewClient creates a Graylog API client. If caCertFile is non-empty, the
// specified CA certificate is loaded and added to the TLS root CA pool.
func NewClient(baseURL, serviceToken, caCertFile string, logger *slog.Logger) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Graylog base URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Graylog base URL %q: scheme and host are required", baseURL)
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected default transport type")
	}
	transport := defaultTransport.Clone()

	if caCertFile != "" {
		caCert, readErr := os.ReadFile(caCertFile) // #nosec G304 -- CA cert path from config, not user input
		if readErr != nil {
			return nil, fmt.Errorf("reading CA certificate file %s: %w", caCertFile, readErr)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
		}

		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport.TLSClientConfig.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	// Normalize base URL by stripping trailing slash.
	normalizedURL := parsed.String()
	if normalizedURL[len(normalizedURL)-1] == '/' {
		normalizedURL = normalizedURL[:len(normalizedURL)-1]
	}

	return &Client{
		httpClient:   httpClient,
		baseURL:      normalizedURL,
		serviceToken: serviceToken,
		logger:       logger,
	}, nil
}

// GetUser retrieves a user by username. It returns (nil, nil) when the user is
// not found (HTTP 404).
func (c *Client) GetUser(ctx context.Context, username string) (*User, error) {
	reqURL := fmt.Sprintf("%s/api/users/%s", c.baseURL, url.PathEscape(username))

	resp, body, err := c.doWithRetry(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getting user %s: %w", username, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting user %s: unexpected status %d: %s", username, resp.StatusCode, truncateBody(body))
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("decoding user response for %s: %w", username, err)
	}

	return &user, nil
}

// CreateUser creates a new user in Graylog.
func (c *Client) CreateUser(ctx context.Context, req *CreateUserRequest) error {
	reqURL := fmt.Sprintf("%s/api/users", c.baseURL)

	payload, err := json.Marshal(req) // #nosec G117 -- password is intentionally in the struct for user creation
	if err != nil {
		return fmt.Errorf("marshaling create user request: %w", err)
	}

	resp, body, err := c.doWithRetry(ctx, http.MethodPost, reqURL, payload)
	if err != nil {
		return fmt.Errorf("creating user %s: %w", req.Username, err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("creating user %s: unexpected status %d: %s", req.Username, resp.StatusCode, truncateBody(body))
	}

	return nil
}

// UpdateUserRoles updates the roles for an existing Graylog user.
func (c *Client) UpdateUserRoles(ctx context.Context, username string, roles []string) error {
	reqURL := fmt.Sprintf("%s/api/users/%s", c.baseURL, url.PathEscape(username))

	payload, err := json.Marshal(map[string][]string{"roles": roles})
	if err != nil {
		return fmt.Errorf("marshaling update roles request: %w", err)
	}

	resp, body, err := c.doWithRetry(ctx, http.MethodPut, reqURL, payload)
	if err != nil {
		return fmt.Errorf("updating roles for user %s: %w", username, err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("updating roles for user %s: unexpected status %d: %s", username, resp.StatusCode, truncateBody(body))
	}

	return nil
}

// Healthy checks whether the Graylog server is reachable and healthy by
// calling the system API endpoint.
func (c *Client) Healthy(ctx context.Context) error {
	reqURL := fmt.Sprintf("%s/api/system", c.baseURL)

	resp, body, err := c.doWithRetry(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check: unexpected status %d: %s", resp.StatusCode, truncateBody(body))
	}

	return nil
}

// doWithRetry executes an HTTP request with up to 3 retry attempts on 5xx
// responses or network errors, using exponential backoff.
func (c *Client) doWithRetry(ctx context.Context, method, reqURL string, jsonBody []byte) (*http.Response, []byte, error) {
	var lastErr error

	for attempt := range maxAttempts {
		if attempt > 0 {
			backoff := retryBackoffs[attempt-1]
			c.logger.DebugContext(ctx, "retrying request",
				slog.String("method", method),
				slog.String("url", reqURL),
				slog.Int("attempt", attempt+1),
				slog.Duration("backoff", backoff))

			select {
			case <-ctx.Done():
				return nil, nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		var bodyReader io.Reader
		if jsonBody != nil {
			bodyReader = bytes.NewReader(jsonBody)
		}

		req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
		if err != nil {
			return nil, nil, fmt.Errorf("building request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.serviceToken)
		req.Header.Set("Accept", "application/json")
		if jsonBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		c.logger.DebugContext(ctx, "sending request",
			slog.String("method", method),
			slog.String("url", reqURL),
			slog.Int("attempt", attempt+1))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			c.logger.DebugContext(ctx, "request error",
				slog.String("method", method),
				slog.String("url", reqURL),
				slog.String("error", err.Error()),
				slog.Int("attempt", attempt+1))
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("reading response body: %w", readErr)
			continue
		}

		c.logger.DebugContext(ctx, "received response",
			slog.String("method", method),
			slog.String("url", reqURL),
			slog.Int("status", resp.StatusCode),
			slog.Int("attempt", attempt+1))

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: status %d", resp.StatusCode)
			continue
		}

		return resp, body, nil
	}

	return nil, nil, fmt.Errorf("all retry attempts exhausted: %w", lastErr)
}

// truncateBody returns the first 512 bytes of a response body for error
// messages, avoiding excessively long log lines.
func truncateBody(body []byte) string {
	if len(body) > 512 {
		return string(body[:512]) + "..."
	}
	return string(body)
}
