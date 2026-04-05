//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/CSTDPP/graylog-auth-proxy/internal/graylog"
)

// sharedEnv holds the shared container infrastructure for all integration tests.
type sharedEnv struct {
	graylogURL string
	apiToken   string
	ctx        context.Context
}

var env *sharedEnv

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Create a shared Docker network so Graylog can reach MongoDB by hostname.
	net, err := network.New(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create docker network: %v", err))
	}

	networkName := net.Name

	// Start MongoDB container.
	mongoReq := testcontainers.ContainerRequest{
		Image:        "mongo:7.0",
		ExposedPorts: []string{"27017/tcp"},
		Networks:     []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"mongo"},
		},
		WaitingFor: wait.ForLog("Waiting for connections").WithStartupTimeout(60 * time.Second),
	}
	mongoC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: mongoReq,
		Started:          true,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to start MongoDB container: %v", err))
	}

	// Start Graylog container.
	graylogReq := testcontainers.ContainerRequest{
		Image:        "graylog/graylog:7.0",
		ExposedPorts: []string{"9000/tcp"},
		Networks:     []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"graylog"},
		},
		Env: map[string]string{
			"GRAYLOG_HTTP_BIND_ADDRESS":    "0.0.0.0:9000",
			"GRAYLOG_MONGODB_URI":          "mongodb://mongo:27017/graylog",
			"GRAYLOG_PASSWORD_SECRET":      "somethinglongenoughforpasswordsecret1234567890",
			"GRAYLOG_ROOT_PASSWORD_SHA2":   "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
			"GRAYLOG_HTTP_EXTERNAL_URI":    "http://localhost:9000/",
		},
		WaitingFor: wait.ForHTTP("/api/system").
			WithPort("9000/tcp").
			WithStatusCodeMatcher(func(status int) bool {
				return status == http.StatusOK || status == http.StatusUnauthorized
			}).
			WithStartupTimeout(120 * time.Second),
	}
	graylogC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: graylogReq,
		Started:          true,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to start Graylog container: %v", err))
	}

	// Resolve the mapped Graylog host and port.
	graylogHost, err := graylogC.Host(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to get Graylog host: %v", err))
	}
	graylogPort, err := graylogC.MappedPort(ctx, "9000/tcp")
	if err != nil {
		panic(fmt.Sprintf("failed to get Graylog mapped port: %v", err))
	}
	graylogURL := fmt.Sprintf("http://%s:%s", graylogHost, graylogPort.Port())

	// Obtain an API token from Graylog using basic auth (admin:admin).
	apiToken, err := createAPIToken(ctx, graylogURL, "admin", "admin")
	if err != nil {
		panic(fmt.Sprintf("failed to create Graylog API token: %v", err))
	}

	env = &sharedEnv{
		graylogURL: graylogURL,
		apiToken:   apiToken,
		ctx:        ctx,
	}

	// Run all tests, then clean up.
	exitCode := m.Run()

	// Terminate containers (best-effort).
	_ = graylogC.Terminate(ctx)
	_ = mongoC.Terminate(ctx)
	_ = net.Remove(ctx)

	if exitCode != 0 {
		panic(fmt.Sprintf("tests failed with exit code %d", exitCode))
	}
}

// createAPIToken generates a Graylog API token via the REST API using basic
// auth credentials. It returns the token string.
func createAPIToken(ctx context.Context, baseURL, username, password string) (string, error) {
	tokenURL := fmt.Sprintf("%s/api/users/%s/tokens/test", baseURL, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader("{}"))
	if err != nil {
		return "", fmt.Errorf("building token request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-By", "integration-test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d creating token: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("received empty token from Graylog")
	}

	return tokenResp.Token, nil
}

// newClient creates a graylog.Client backed by the shared test environment.
func newClient(t *testing.T) *graylog.Client {
	t.Helper()
	logger := slog.Default()
	client, err := graylog.NewClient(env.graylogURL, env.apiToken, "", logger)
	require.NoError(t, err, "creating graylog client")
	return client
}

func TestIntegration_UserProvisioning(t *testing.T) {
	ctx := env.ctx
	client := newClient(t)

	// GetUser for a non-existent user should return nil, nil.
	t.Run("GetUser_NonExistent", func(t *testing.T) {
		user, err := client.GetUser(ctx, "nonexistent-user")
		require.NoError(t, err)
		assert.Nil(t, user, "expected nil for non-existent user")
	})

	// CreateUser should succeed.
	testUsername := fmt.Sprintf("testuser-%d", time.Now().UnixNano())
	t.Run("CreateUser", func(t *testing.T) {
		err := client.CreateUser(ctx, &graylog.CreateUserRequest{
			Username:    testUsername,
			Email:       testUsername + "@example.com",
			FullName:    "Integration Test User",
			Password:    "S3cureP@ssword!",
			Roles:       []string{"Reader"},
			Permissions: []string{"*"},
		})
		require.NoError(t, err, "creating user should succeed")
	})

	// GetUser should find the newly created user.
	t.Run("GetUser_Exists", func(t *testing.T) {
		user, err := client.GetUser(ctx, testUsername)
		require.NoError(t, err)
		require.NotNil(t, user, "expected user to exist after creation")
		assert.Equal(t, testUsername, user.Username)
		assert.Equal(t, testUsername+"@example.com", user.Email)
		assert.Equal(t, "Integration Test User", user.FullName)
		assert.Contains(t, user.Roles, "Reader")
	})

	// UpdateUserRoles should change roles.
	t.Run("UpdateUserRoles", func(t *testing.T) {
		newRoles := []string{"Admin", "Reader"}
		err := client.UpdateUserRoles(ctx, testUsername, newRoles)
		require.NoError(t, err, "updating roles should succeed")

		// Verify the roles were updated.
		user, err := client.GetUser(ctx, testUsername)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.ElementsMatch(t, newRoles, user.Roles, "roles should match after update")
	})
}

func TestIntegration_HealthCheck(t *testing.T) {
	ctx := env.ctx
	client := newClient(t)

	err := client.Healthy(ctx)
	assert.NoError(t, err, "Graylog should be healthy")
}
