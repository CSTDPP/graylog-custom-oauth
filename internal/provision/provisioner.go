package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/CSTDPP/graylog-auth-proxy/internal/graylog"
)

// UserInfo contains the identity and role information needed to provision a
// Graylog user. Roles must already be mapped to Graylog role names.
type UserInfo struct {
	Username string
	Email    string
	Name     string
	Roles    []string
}

// GraylogClient is the subset of graylog.Client used by the Provisioner.
type GraylogClient interface {
	GetUser(ctx context.Context, username string) (*graylog.User, error)
	CreateUser(ctx context.Context, req graylog.CreateUserRequest) error
	UpdateUserRoles(ctx context.Context, username string, roles []string) error
}

// Provisioner ensures that an authenticated user exists in Graylog with the
// correct roles. It is safe to call Provision on every login; the operation is
// idempotent.
type Provisioner struct {
	client GraylogClient
	logger *slog.Logger
}

// NewProvisioner creates a Provisioner backed by the given Graylog API client.
func NewProvisioner(client GraylogClient) *Provisioner {
	return &Provisioner{
		client: client,
		logger: slog.Default(),
	}
}

// Provision ensures the user described by info exists in Graylog and has the
// specified roles. If the user does not exist it is created with a random
// password. Roles are always synchronised regardless of whether the user was
// just created.
func (p *Provisioner) Provision(ctx context.Context, info UserInfo) error {
	user, err := p.client.GetUser(ctx, info.Username)
	if err != nil {
		return fmt.Errorf("looking up user %s: %w", info.Username, err)
	}

	if user == nil {
		password, genErr := randomPassword(32)
		if genErr != nil {
			return fmt.Errorf("generating password for user %s: %w", info.Username, genErr)
		}

		createReq := graylog.CreateUserRequest{
			Username:    info.Username,
			Email:       info.Email,
			FullName:    info.Name,
			Password:    password,
			Roles:       info.Roles,
			Permissions: []string{},
		}

		if err := p.client.CreateUser(ctx, createReq); err != nil {
			return fmt.Errorf("creating user %s: %w", info.Username, err)
		}

		p.logger.InfoContext(ctx, "created graylog user",
			slog.String("username", info.Username),
			slog.String("email", info.Email))
	}

	if err := p.client.UpdateUserRoles(ctx, info.Username, info.Roles); err != nil {
		return fmt.Errorf("updating roles for user %s: %w", info.Username, err)
	}

	p.logger.InfoContext(ctx, "synced graylog user roles",
		slog.String("username", info.Username),
		slog.Any("roles", info.Roles))

	return nil
}

// randomPassword generates a cryptographically random hex-encoded password of
// the specified byte length (the returned string is twice as long).
func randomPassword(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
