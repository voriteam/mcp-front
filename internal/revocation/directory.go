package revocation

import (
	"context"
	"errors"
	"fmt"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// Status describes the state of a Google Workspace account.
type Status int

const (
	// StatusActive means the account exists and is not suspended.
	StatusActive Status = iota
	// StatusSuspended means the account exists but is suspended.
	StatusSuspended
	// StatusDeleted means the account no longer exists.
	StatusDeleted
)

func (s Status) String() string {
	switch s {
	case StatusSuspended:
		return "suspended"
	case StatusDeleted:
		return "deleted"
	default:
		return "active"
	}
}

// Disabled reports whether the status warrants revoking the user's access.
func (s Status) Disabled() bool {
	return s == StatusSuspended || s == StatusDeleted
}

// DirectoryConfig configures access to the Google Workspace Directory API.
type DirectoryConfig struct {
	// AdminEmail is the Workspace admin user the service account impersonates
	// (the domain-wide delegation subject).
	AdminEmail string
	// ImpersonateServiceAccount is the service account to impersonate for keyless
	// domain-wide delegation. When empty, Application Default Credentials are used
	// directly (which only works if those credentials already carry the delegation
	// subject).
	ImpersonateServiceAccount string
}

// DirectoryClient looks up Google Workspace account status via the Admin SDK
// Directory API.
type DirectoryClient struct {
	svc *admin.Service
}

// NewDirectoryClient builds a Directory API client using Application Default
// Credentials, optionally via keyless service-account impersonation for
// domain-wide delegation.
func NewDirectoryClient(ctx context.Context, cfg DirectoryConfig) (*DirectoryClient, error) {
	if cfg.AdminEmail == "" {
		return nil, fmt.Errorf("admin email (delegation subject) is required")
	}

	opts := []option.ClientOption{option.WithScopes(admin.AdminDirectoryUserReadonlyScope)}
	if cfg.ImpersonateServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: cfg.ImpersonateServiceAccount,
			Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
			Subject:         cfg.AdminEmail,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create impersonated token source: %w", err)
		}
		opts = []option.ClientOption{option.WithTokenSource(ts)}
	}

	svc, err := admin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Directory API client: %w", err)
	}

	return &DirectoryClient{svc: svc}, nil
}

// Status returns the Workspace account status for an email. A 404 from the
// Directory API is mapped to StatusDeleted; any other API error is returned so
// the caller can skip (rather than revoke) on transient failures.
func (c *DirectoryClient) Status(ctx context.Context, email string) (Status, error) {
	user, err := c.svc.Users.Get(email).Context(ctx).Do()
	if err != nil {
		var gerr *googleapi.Error
		if errors.As(err, &gerr) && gerr.Code == 404 {
			return StatusDeleted, nil
		}
		return StatusActive, fmt.Errorf("directory lookup for %s: %w", email, err)
	}
	if user.Suspended {
		return StatusSuspended, nil
	}
	return StatusActive, nil
}
