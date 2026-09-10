package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/storage"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	// OAuthStateExpiry is how long OAuth state parameters remain valid
	OAuthStateExpiry = 10 * time.Minute

	// TokenRefreshThreshold is how early to refresh tokens before expiry
	// Set to 5 minutes to prevent tokens expiring mid-operation when users
	// are in Claude and cannot easily re-authenticate
	TokenRefreshThreshold = 5 * time.Minute
)

// serviceStorage combines the storage interfaces needed by ServiceOAuthClient
type serviceStorage interface {
	storage.UserTokenStore
	storage.ServiceRegistrationStore
}

// ServiceOAuthClient handles OAuth flows for external MCP services
type ServiceOAuthClient struct {
	storage     serviceStorage
	baseURL     string
	httpClient  *http.Client
	stateSigner crypto.TokenSigner

	discoveryCache sync.Map
	discoveryGroup singleflight.Group
}

// ServiceOAuthState stores OAuth flow state for external service authentication (mcp-front → external service)
type ServiceOAuthState struct {
	Service      string    `json:"service"`
	UserEmail    string    `json:"user_email"`
	ReturnURL    string    `json:"return_url,omitempty"`
	PKCEVerifier string    `json:"pkce_verifier"`
	CreatedAt    time.Time `json:"created_at"`
}

// CallbackResult contains the result of a successful OAuth callback
type CallbackResult struct {
	UserEmail string
	ReturnURL string
}

// NewServiceOAuthClient creates a new OAuth client for external services
func NewServiceOAuthClient(store serviceStorage, baseURL string, signingKey []byte) *ServiceOAuthClient {
	return &ServiceOAuthClient{
		storage:     store,
		baseURL:     baseURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		stateSigner: crypto.NewTokenSigner(signingKey, OAuthStateExpiry),
	}
}

// resolvedOAuth is the effective OAuth configuration for a service: config values
// where the operator supplied them, discovered values everywhere else.
type resolvedOAuth struct {
	clientID         string
	clientSecret     string
	authorizationURL string
	tokenURL         string
	registrationURL  string
	issuer           string
	scopes           []string
	discovered       bool
}

// getOAuth2Config builds an oauth2.Config for the given service, performing dynamic
// client registration if no clientId is configured.
func (c *ServiceOAuthClient) getOAuth2Config(ctx context.Context, serviceName string, serverConfig *config.MCPClientConfig) (*oauth2.Config, error) {
	resolved, err := c.resolveOAuth(ctx, serviceName, serverConfig)
	if err != nil {
		return nil, err
	}

	clientID := resolved.clientID
	clientSecret := resolved.clientSecret

	if clientID == "" {
		reg, err := c.getOrRegisterClient(ctx, serviceName, resolved)
		if err != nil {
			return nil, fmt.Errorf("dynamic client registration failed: %w", err)
		}
		clientID = reg.ClientID
		clientSecret = reg.ClientSecret
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  resolved.authorizationURL,
			TokenURL: resolved.tokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      resolved.scopes,
	}, nil
}

// Discovery also runs when only the client credentials are missing, because the
// registration endpoint lives at the issuer, which need not share a host with the
// authorization endpoint the config names.
func (c *ServiceOAuthClient) resolveOAuth(ctx context.Context, serviceName string, serverConfig *config.MCPClientConfig) (*resolvedOAuth, error) {
	auth := serverConfig.UserAuthentication
	resolved := &resolvedOAuth{
		clientID:         string(auth.ClientID),
		clientSecret:     string(auth.ClientSecret),
		authorizationURL: auth.AuthorizationURL,
		tokenURL:         auth.TokenURL,
		scopes:           auth.Scopes,
	}

	endpointsConfigured := resolved.authorizationURL != "" && resolved.tokenURL != ""
	if endpointsConfigured && resolved.clientID != "" {
		return resolved, nil
	}

	discovered, err := c.discover(ctx, serviceName, serverConfig)
	if err != nil {
		if !endpointsConfigured {
			return nil, err
		}
		log.LogInfoWithFields("service_oauth", "Registering against the configured authorization endpoint's own origin", map[string]any{
			"service": serviceName,
			"reason":  err.Error(),
		})
		return resolved, nil
	}

	if resolved.authorizationURL == "" {
		resolved.authorizationURL = discovered.AuthorizationURL
	}
	if resolved.tokenURL == "" {
		resolved.tokenURL = discovered.TokenURL
	}
	if len(resolved.scopes) == 0 {
		resolved.scopes = discovered.Scopes
	}
	resolved.registrationURL = discovered.RegistrationURL
	resolved.issuer = discovered.Issuer
	resolved.discovered = true

	if resolved.authorizationURL == "" || resolved.tokenURL == "" {
		return nil, fmt.Errorf("authorization server %s advertises no authorization_endpoint or token_endpoint: set authorizationUrl and tokenUrl for service %s", discovered.Issuer, serviceName)
	}

	return resolved, nil
}

func (c *ServiceOAuthClient) discover(ctx context.Context, serviceName string, serverConfig *config.MCPClientConfig) (*discoveredOAuth, error) {
	if cached, ok := c.discoveryCache.Load(serviceName); ok {
		return cached.(*discoveredOAuth), nil
	}

	if !serverConfig.CanDiscoverOAuth() {
		return nil, fmt.Errorf("service %s has no discoverable url: set userAuthentication.authorizationUrl and tokenUrl", serviceName)
	}

	result, err, _ := c.discoveryGroup.Do(serviceName, func() (any, error) {
		if cached, ok := c.discoveryCache.Load(serviceName); ok {
			return cached, nil
		}

		// Detached from the caller: the result is shared with every concurrent
		// caller, and token refresh runs on a request that can disconnect.
		discoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryChainTimeout)
		defer cancel()

		discovered, err := discoverOAuth(discoveryCtx, c.httpClient, serverConfig.TransportType, serverConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("discovering the OAuth endpoints of service %s: %w", serviceName, err)
		}

		c.discoveryCache.Store(serviceName, discovered)
		log.LogInfoWithFields("service_oauth", "Discovered OAuth endpoints from backend", map[string]any{
			"service":          serviceName,
			"issuer":           discovered.Issuer,
			"authorizationUrl": discovered.AuthorizationURL,
			"tokenUrl":         discovered.TokenURL,
		})
		return discovered, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*discoveredOAuth), nil
}

// getOrRegisterClient returns a stored service registration, registering dynamically if needed.
func (c *ServiceOAuthClient) getOrRegisterClient(ctx context.Context, serviceName string, resolved *resolvedOAuth) (*storage.ServiceRegistration, error) {
	reg, err := c.storage.GetServiceRegistration(ctx, serviceName)
	if err == nil {
		if reg.ExpiresAt.IsZero() || time.Now().Before(reg.ExpiresAt) {
			return reg, nil
		}
		log.LogInfoWithFields("service_oauth", "Service registration expired, re-registering", map[string]any{
			"service": serviceName,
		})
	} else if !errors.Is(err, storage.ErrServiceRegistrationNotFound) {
		return nil, fmt.Errorf("failed to get service registration: %w", err)
	}

	return c.registerClient(ctx, serviceName, resolved)
}

// registerClient performs RFC 7591 dynamic client registration with the upstream service.
func (c *ServiceOAuthClient) registerClient(ctx context.Context, serviceName string, resolved *resolvedOAuth) (*storage.ServiceRegistration, error) {
	registrationURL, err := c.registrationEndpoint(ctx, resolved)
	if err != nil {
		return nil, fmt.Errorf("failed to discover registration endpoint: %w", err)
	}

	redirectURI := fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName)

	reqBody := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"client_name":                "mcp-front",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	if len(resolved.scopes) > 0 {
		reqBody["scope"] = strings.Join(resolved.scopes, " ")
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, body)
	}

	var regResp struct {
		ClientID              string `json:"client_id"`
		ClientSecret          string `json:"client_secret,omitempty"`
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}

	if regResp.ClientID == "" {
		return nil, fmt.Errorf("registration response missing client_id")
	}

	reg := &storage.ServiceRegistration{
		ServiceName:  serviceName,
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		CreatedAt:    time.Now(),
	}
	if regResp.ClientSecretExpiresAt > 0 {
		reg.ExpiresAt = time.Unix(regResp.ClientSecretExpiresAt, 0)
	}

	if err := c.storage.SetServiceRegistration(ctx, serviceName, reg); err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to store service registration", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
	}

	log.LogInfoWithFields("service_oauth", "Dynamically registered client with service", map[string]any{
		"service":   serviceName,
		"client_id": regResp.ClientID,
	})

	return reg, nil
}

// Without discovery there is no issuer to ask, so the authorization endpoint's own
// origin stands in for one.
func (c *ServiceOAuthClient) registrationEndpoint(ctx context.Context, resolved *resolvedOAuth) (string, error) {
	if resolved.discovered {
		if resolved.registrationURL == "" {
			return "", fmt.Errorf("authorization server %s advertises no registration_endpoint: set clientId and clientSecret", resolved.issuer)
		}
		return resolved.registrationURL, nil
	}

	u, err := url.Parse(resolved.authorizationURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization URL: %w", err)
	}

	meta, err := fetchAuthServerMetadata(ctx, c.httpClient, u.Scheme+"://"+u.Host)
	if err != nil {
		return "", err
	}
	if meta.RegistrationEndpoint == "" {
		return "", fmt.Errorf("OAuth metadata missing registration_endpoint")
	}
	return meta.RegistrationEndpoint, nil
}

// StartOAuthFlow initiates OAuth flow for a service
func (c *ServiceOAuthClient) StartOAuthFlow(
	ctx context.Context,
	userEmail string,
	serviceName string,
	returnURL string,
	serviceConfig *config.MCPClientConfig,
) (string, error) {
	if serviceConfig.UserAuthentication == nil ||
		serviceConfig.UserAuthentication.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, serviceConfig)
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth config: %w", err)
	}

	verifier := oauth2.GenerateVerifier()

	// Generate signed state parameter (stateless - no cache needed)
	stateData := ServiceOAuthState{
		Service:      serviceName,
		UserEmail:    userEmail,
		ReturnURL:    returnURL,
		PKCEVerifier: verifier,
		CreatedAt:    time.Now(),
	}

	state, err := c.stateSigner.Sign(stateData)
	if err != nil {
		return "", fmt.Errorf("failed to sign state: %w", err)
	}

	// Generate authorization URL with PKCE (S256)
	authURL := oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	log.LogInfoWithFields("service_oauth", "Starting OAuth flow", map[string]any{
		"service":  serviceName,
		"user":     userEmail,
		"authURL":  authURL,
		"redirect": oauth2Config.RedirectURL,
	})

	return authURL, nil
}

// HandleCallback processes OAuth callback
func (c *ServiceOAuthClient) HandleCallback(
	ctx context.Context,
	serviceName string,
	code string,
	state string,
	serviceConfig *config.MCPClientConfig,
) (*CallbackResult, error) {
	// Verify and decode signed state
	var stateData ServiceOAuthState
	if err := c.stateSigner.Verify(state, &stateData); err != nil {
		return nil, fmt.Errorf("invalid or expired state parameter: %w", err)
	}

	// Validate service matches
	if stateData.Service != serviceName {
		return nil, fmt.Errorf("service mismatch in OAuth callback")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return nil, fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth config: %w", err)
	}

	// Exchange code for token with PKCE verifier
	token, err := oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(stateData.PKCEVerifier))
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to exchange code for token", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Store the token
	storedToken := &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.Expiry,
			TokenType:    token.TokenType,
			Scopes:       oauth2Config.Scopes,
		},
		UpdatedAt: time.Now(),
	}

	if err := c.storage.SetUserToken(ctx, stateData.UserEmail, serviceName, storedToken); err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to store OAuth token", map[string]any{
			"service": serviceName,
			"user":    stateData.UserEmail,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "OAuth flow completed successfully", map[string]any{
		"service": serviceName,
		"user":    stateData.UserEmail,
	})

	return &CallbackResult{
		UserEmail: stateData.UserEmail,
		ReturnURL: stateData.ReturnURL,
	}, nil
}

// RefreshToken refreshes an OAuth token if needed
func (c *ServiceOAuthClient) RefreshToken(
	ctx context.Context,
	userEmail string,
	serviceName string,
	serviceConfig *config.MCPClientConfig,
) error {
	// Get current token
	storedToken, err := c.storage.GetUserToken(ctx, userEmail, serviceName)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if storedToken.Type != storage.TokenTypeOAuth || storedToken.OAuthData == nil {
		return fmt.Errorf("token is not an OAuth token")
	}

	// Early refresh strategy: Refresh tokens TokenRefreshThreshold before expiry
	//
	// Why 5 minutes?
	// - Users are in Claude.ai, not mcp-front UI. If token expires mid-session,
	//   they see cryptic "tool failed" errors with no way to re-auth without
	//   leaving Claude.
	// - Stdio processes are created on-demand. Token is fetched from storage and
	//   injected into process env. If storage has expired token, process fails
	//   to connect to external service.
	// - Early refresh prevents these failures. Cost is negligible (one HTTP request
	//   per service per hour vs broken user workflow).
	//
	// Why not background refresh job?
	// - mcp-front is request-driven. Tokens are fetched when stdio sessions are
	//   created (user triggers operation in Claude). Refreshing on request path
	//   is simpler and aligns with the architecture.
	// - Background jobs require distributed coordination for multi-instance deploys,
	//   lifecycle management, and handling refresh failures asynchronously.
	if time.Until(storedToken.OAuthData.ExpiresAt) > TokenRefreshThreshold {
		return nil // Token still valid, no refresh needed
	}

	if storedToken.OAuthData.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return fmt.Errorf("service configuration missing OAuth settings")
	}

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, serviceConfig)
	if err != nil {
		return fmt.Errorf("failed to get OAuth config: %w", err)
	}

	// Create token for refresh
	oldToken := &oauth2.Token{
		AccessToken:  storedToken.OAuthData.AccessToken,
		RefreshToken: storedToken.OAuthData.RefreshToken,
		Expiry:       storedToken.OAuthData.ExpiresAt,
		TokenType:    storedToken.OAuthData.TokenType,
	}

	// Use ReuseTokenSourceWithExpiry to enforce our 5-minute early refresh threshold.
	// The default TokenSource only refreshes when token is expired. We want to refresh
	// earlier to prevent tokens expiring mid-operation. The earlyExpiry parameter
	// tells the oauth2 library to consider tokens expired 5 minutes before their
	// actual expiry time.
	//
	// Division of responsibility:
	// - We decide WHEN to refresh (5-minute threshold via our check + earlyExpiry)
	// - oauth2 library decides HOW to refresh (HTTP request format, error handling,
	//   refresh token rotation, provider-specific quirks across OAuth providers)
	baseSource := oauth2Config.TokenSource(ctx, oldToken)
	earlyRefreshSource := oauth2.ReuseTokenSourceWithExpiry(oldToken, baseSource, TokenRefreshThreshold)
	newToken, err := earlyRefreshSource.Token()
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to refresh token", map[string]any{
			"service": serviceName,
			"user":    userEmail,
			"error":   err.Error(),
		})

		if isUnrecoverableTokenError(err) {
			if delErr := c.storage.DeleteUserToken(ctx, userEmail, serviceName); delErr != nil {
				log.LogErrorWithFields("service_oauth", "Failed to delete invalid token", map[string]any{
					"service": serviceName,
					"user":    userEmail,
					"error":   delErr.Error(),
				})
			} else {
				log.LogInfoWithFields("service_oauth", "Deleted invalid token after refresh failure", map[string]any{
					"service": serviceName,
					"user":    userEmail,
				})
			}
		}

		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update stored token
	storedToken.OAuthData.AccessToken = newToken.AccessToken
	if newToken.RefreshToken != "" {
		storedToken.OAuthData.RefreshToken = newToken.RefreshToken
	}
	storedToken.OAuthData.ExpiresAt = newToken.Expiry
	storedToken.UpdatedAt = time.Now()

	if err := c.storage.SetUserToken(ctx, userEmail, serviceName, storedToken); err != nil {
		return fmt.Errorf("failed to store refreshed token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "Token refreshed successfully", map[string]any{
		"service": serviceName,
		"user":    userEmail,
		"expiry":  newToken.Expiry,
	})

	return nil
}

// isUnrecoverableTokenError returns true if the error indicates the refresh
// token is permanently invalid and the user must re-authenticate.
func isUnrecoverableTokenError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "invalid_client") ||
		strings.Contains(msg, "unauthorized_client")
}

// GetConnectURL generates the OAuth connect URL for a service
func (c *ServiceOAuthClient) GetConnectURL(serviceName string, returnPath string) string {
	params := url.Values{}
	params.Set("service", serviceName)
	if returnPath != "" {
		params.Set("return", returnPath)
	}
	return fmt.Sprintf("%s/oauth/connect?%s", c.baseURL, params.Encode())
}
