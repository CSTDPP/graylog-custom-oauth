package jwt

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims holds the identity information extracted from a validated ID token.
type Claims struct {
	Username string
	Name     string
	Email    string
	Roles    []string
}

// Validator verifies Microsoft Entra ID tokens using JWKS-based signature
// validation and extracts identity claims.
type Validator struct {
	verifier *oidc.IDTokenVerifier
}

// NewValidator creates a Validator that verifies tokens issued by the given
// Entra tenant for the specified client (audience). It fetches the OIDC
// discovery document and JWKS key set during construction.
func NewValidator(ctx context.Context, tenantID, clientID string) (*Validator, error) {
	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider for tenant %s: %w", tenantID, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &Validator{verifier: verifier}, nil
}

// Validate verifies the raw JWT token signature against the JWKS key set and
// extracts identity claims. The username is resolved from preferred_username,
// falling back to upn, then sub. Roles default to an empty slice when the
// claim is absent.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verifying ID token: %w", err)
	}

	var raw struct {
		PreferredUsername string   `json:"preferred_username"`
		UPN               string   `json:"upn"`
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		Email             string   `json:"email"`
		Roles             []string `json:"roles"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("extracting token claims: %w", err)
	}

	username := raw.PreferredUsername
	if username == "" {
		username = raw.UPN
	}
	if username == "" {
		username = raw.Sub
	}

	roles := raw.Roles
	if roles == nil {
		roles = []string{}
	}

	return &Claims{
		Username: username,
		Name:     raw.Name,
		Email:    raw.Email,
		Roles:    roles,
	}, nil
}
