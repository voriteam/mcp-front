package storage

import (
	"context"
	"errors"
	"time"

	"github.com/stainless-api/mcp-front/internal/oauth"
)

var ErrUserTokenNotFound = errors.New("user token not found")
var ErrClientNotFound = errors.New("client not found")
var ErrGrantNotFound = errors.New("grant not found")
var ErrServiceRegistrationNotFound = errors.New("service registration not found")

type TokenType string

const (
	TokenTypeManual TokenType = "manual"
	TokenTypeOAuth  TokenType = "oauth"
)

type OAuthTokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

type StoredToken struct {
	Type      TokenType       `json:"type"`
	Value     string          `json:"value,omitempty"`
	OAuthData *OAuthTokenData `json:"oauth,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type ActiveSession struct {
	SessionID  string    `json:"session_id"`
	UserEmail  string    `json:"user_email"`
	ServerName string    `json:"server_name"`
	Created    time.Time `json:"created"`
	LastActive time.Time `json:"last_active"`
}

type UserTokenStore interface {
	GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error)
	SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
}

type ServiceRegistration struct {
	ServiceName  string    `json:"service_name"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type ServiceRegistrationStore interface {
	GetServiceRegistration(ctx context.Context, serviceName string) (*ServiceRegistration, error)
	SetServiceRegistration(ctx context.Context, serviceName string, reg *ServiceRegistration) error
}

// RevocationStore persists the set of user emails whose access has been revoked
// (e.g. their Google Workspace account was suspended or deleted). The set is a
// mirror of "currently disabled" — entries are added when an account is found
// disabled and removed when it is re-enabled.
type RevocationStore interface {
	AddRevokedUser(ctx context.Context, userEmail, reason string) error
	RemoveRevokedUser(ctx context.Context, userEmail string) error
	IsUserRevoked(ctx context.Context, userEmail string) (bool, error)
	ListRevokedUsers(ctx context.Context) ([]string, error)
}

type Storage interface {
	// OAuth client management
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error)
	CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error)

	// Grant management (authorization codes)
	StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error
	ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error)

	// User token storage
	UserTokenStore

	// Service registration (for dynamic client registration with upstream services)
	ServiceRegistrationStore

	// Revocation set (for disabled-account enforcement)
	RevocationStore

	// Session tracking
	TrackSession(ctx context.Context, session ActiveSession) error
	RevokeSession(ctx context.Context, sessionID string) error

	// Reconciliation helpers (used by the revocation background job)
	ListUsersWithTokens(ctx context.Context) ([]string, error)
	ListUsersWithSessions(ctx context.Context) ([]string, error)
	RevokeUserSessions(ctx context.Context, userEmail string) error
}
