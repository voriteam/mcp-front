package storage

import (
	"context"
	"errors"
	"time"

	"github.com/stainless-api/mcp-front/internal/oauth"
)

var ErrUserTokenNotFound = errors.New("user token not found")
var ErrIdentityTokenNotFound = errors.New("identity token not found")
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

// IdentityTokenStore persists the identity provider's refresh token for each
// user, captured at login. The account verifier replays it against the IdP to
// detect when a user's account is no longer active (e.g. suspended or deleted).
type IdentityTokenStore interface {
	SetIdentityToken(ctx context.Context, userEmail, refreshToken string) error
	GetIdentityToken(ctx context.Context, userEmail string) (string, error)
	DeleteIdentityToken(ctx context.Context, userEmail string) error
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

	// Identity provider refresh tokens (for disabled-account enforcement)
	IdentityTokenStore

	// Session tracking
	TrackSession(ctx context.Context, session ActiveSession) error
	RevokeSession(ctx context.Context, sessionID string) error

	// RevokeUserSessions removes all sessions for a user (used when purging a
	// revoked account).
	RevokeUserSessions(ctx context.Context, userEmail string) error
}
