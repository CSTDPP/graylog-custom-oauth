package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/CSTDPP/graylog-auth-proxy/internal/graylog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGraylogClient implements GraylogClient with controllable return values.
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

func (m *mockGraylogClient) UpdateUserRoles(ctx context.Context, username string, roles []string) error {
	return m.updateUserRoles(ctx, username, roles)
}

func TestProvision_UserExists_OnlyUpdatesRoles(t *testing.T) {
	createCalled := false
	var updatedRoles []string

	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return &graylog.User{
				Username: "alice",
				Email:    "alice@example.com",
				FirstName: "Alice",
				LastName:  "User",
				Roles:    []string{"Reader"},
			}, nil
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			createCalled = true
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, roles []string) error {
			updatedRoles = roles
			return nil
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice",
		Roles:    []string{"Admin", "Reader"},
	})

	require.NoError(t, err)
	assert.False(t, createCalled, "CreateUser should not be called for existing user")
	assert.Equal(t, []string{"Admin", "Reader"}, updatedRoles)
}

func TestProvision_UserMissing_CreatesAndUpdatesRoles(t *testing.T) {
	createCalled := false
	updateCalled := false
	var capturedReq *graylog.CreateUserRequest

	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return nil, nil
		},
		createUser: func(_ context.Context, req *graylog.CreateUserRequest) error {
			createCalled = true
			capturedReq = req
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			updateCalled = true
			return nil
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{
		Username: "bob",
		Email:    "bob@example.com",
		Name:     "Bob",
		Roles:    []string{"Reader"},
	})

	require.NoError(t, err)
	assert.True(t, createCalled, "CreateUser should be called for missing user")
	assert.True(t, updateCalled, "UpdateUserRoles should be called after creation")
	assert.Equal(t, "bob", capturedReq.Username)
	assert.NotEmpty(t, capturedReq.Password)
}

func TestProvision_GetUserError_ReturnsError(t *testing.T) {
	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return nil, errors.New("connection refused")
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			t.Fatal("CreateUser should not be called")
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			t.Fatal("UpdateUserRoles should not be called")
			return nil
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{Username: "carol"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "looking up user")
}

func TestProvision_CreateUserError_ReturnsError(t *testing.T) {
	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return nil, nil
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			return errors.New("409 conflict")
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			t.Fatal("UpdateUserRoles should not be called after create error")
			return nil
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{
		Username: "dave",
		Email:    "dave@example.com",
		Name:     "Dave",
		Roles:    []string{"Reader"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating user")
}

func TestProvision_UpdateRolesError_ReturnsError(t *testing.T) {
	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return &graylog.User{Username: "eve"}, nil
		},
		createUser: func(_ context.Context, _ *graylog.CreateUserRequest) error {
			t.Fatal("CreateUser should not be called")
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			return errors.New("internal server error")
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{
		Username: "eve",
		Roles:    []string{"Admin"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "updating roles")
}

func TestProvision_CreatedUserHasRandomPassword(t *testing.T) {
	var capturedReq *graylog.CreateUserRequest

	mock := &mockGraylogClient{
		getUser: func(_ context.Context, _ string) (*graylog.User, error) {
			return nil, nil
		},
		createUser: func(_ context.Context, req *graylog.CreateUserRequest) error {
			capturedReq = req
			return nil
		},
		updateUserRoles: func(_ context.Context, _ string, _ []string) error {
			return nil
		},
	}

	p := NewProvisioner(mock)
	err := p.Provision(context.Background(), UserInfo{
		Username: "frank",
		Email:    "frank@example.com",
		Name:     "Frank",
		Roles:    []string{"Reader"},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, capturedReq.Password)
	// 32 random bytes encoded as hex = 64 characters.
	assert.Len(t, capturedReq.Password, 64, "password should be 32 bytes hex-encoded (64 chars)")
}
