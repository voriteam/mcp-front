package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartOAuthFlow(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	serviceConfig := &config.MCPClientConfig{
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         "https://service.example.com/oauth/token",
			Scopes:           []string{"read", "write"},
		},
	}

	authURL, err := client.StartOAuthFlow(
		context.Background(),
		"user@example.com",
		"test-service",
		"/my/tokens",
		serviceConfig,
	)

	require.NoError(t, err)
	assert.Contains(t, authURL, "https://service.example.com/oauth/authorize")
	assert.Contains(t, authURL, "client_id=test-client-id")
	assert.Contains(t, authURL, "redirect_uri=https%3A%2F%2Fmcp-front.example.com%2Foauth%2Fcallback%2Ftest-service")
	assert.Contains(t, authURL, "scope=read+write")
	assert.Contains(t, authURL, "state=") // State should be present
}

func TestHandleCallback(t *testing.T) {
	// Create mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// oauth2 library handles the request format, just return tokens
		response := map[string]any{
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer tokenServer.Close()

	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	serviceConfig := &config.MCPClientConfig{
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         tokenServer.URL,
			Scopes:           []string{"read", "write"},
		},
	}

	// Start flow to get state from URL
	authURL, err := client.StartOAuthFlow(
		context.Background(),
		"user@example.com",
		"test-service",
		"/oauth/services?state=abc",
		serviceConfig,
	)
	require.NoError(t, err)

	// Extract state from authorization URL
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	require.NotEmpty(t, state)

	// Handle callback
	result, err := client.HandleCallback(
		context.Background(),
		"test-service",
		"test-code",
		state,
		serviceConfig,
	)

	require.NoError(t, err)
	assert.Equal(t, "user@example.com", result.UserEmail)
	assert.Equal(t, "/oauth/services?state=abc", result.ReturnURL)

	// Verify token was stored
	storedToken, err := store.GetUserToken(context.Background(), "user@example.com", "test-service")
	require.NoError(t, err)
	assert.Equal(t, storage.TokenTypeOAuth, storedToken.Type)
	assert.Equal(t, "mock-access-token", storedToken.OAuthData.AccessToken)
	assert.Equal(t, "mock-refresh-token", storedToken.OAuthData.RefreshToken)

}

func TestRefreshToken(t *testing.T) {
	// Create mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))

		response := map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer tokenServer.Close()

	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	// Store a token expiring in 2 minutes (within our 5-minute refresh threshold)
	// This tests our early refresh logic, not just "can refresh expired tokens"
	oldToken := &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  "old-access-token",
			RefreshToken: "old-refresh-token",
			ExpiresAt:    time.Now().Add(2 * time.Minute), // Expires soon, triggers early refresh
			TokenType:    "Bearer",
			Scopes:       []string{"read", "write"},
		},
		UpdatedAt: time.Now(),
	}

	err := store.SetUserToken(context.Background(), "user@example.com", "test-service", oldToken)
	require.NoError(t, err)

	serviceConfig := &config.MCPClientConfig{
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         tokenServer.URL,
			Scopes:           []string{"read", "write"},
		},
	}

	// Refresh token
	err = client.RefreshToken(
		context.Background(),
		"user@example.com",
		"test-service",
		serviceConfig,
	)

	require.NoError(t, err)

	// Verify token was updated
	refreshedToken, err := store.GetUserToken(context.Background(), "user@example.com", "test-service")
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", refreshedToken.OAuthData.AccessToken)
	assert.Equal(t, "new-refresh-token", refreshedToken.OAuthData.RefreshToken)
}

func TestGetConnectURL(t *testing.T) {
	client := NewServiceOAuthClient(nil, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	t.Run("with return path", func(t *testing.T) {
		url := client.GetConnectURL("my-service", "/my/tokens")
		assert.Equal(t, "https://mcp-front.example.com/oauth/connect?return=%2Fmy%2Ftokens&service=my-service", url)
	})

	t.Run("without return path", func(t *testing.T) {
		url := client.GetConnectURL("my-service", "")
		assert.Equal(t, "https://mcp-front.example.com/oauth/connect?service=my-service", url)
	})
}

func serviceOAuthTestClient(t *testing.T) *ServiceOAuthClient {
	t.Helper()
	return NewServiceOAuthClient(storage.NewMemoryStorage(), "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))
}

func discoverableServer(url string, auth *config.UserAuthentication) *config.MCPClientConfig {
	return &config.MCPClientConfig{
		TransportType:      config.MCPClientTypeStreamable,
		URL:                url,
		RequiresUserToken:  true,
		UserAuthentication: auth,
	}
}

func TestResolveOAuthDiscoversWhatConfigOmits(t *testing.T) {
	b := &backend{}
	server := b.start(t)
	client := serviceOAuthTestClient(t)

	resolved, err := client.resolveOAuth(context.Background(), "someserver", discoverableServer(b.resourceURL(server), &config.UserAuthentication{
		Type:        config.UserAuthTypeOAuth,
		DisplayName: "Some Server",
	}))
	require.NoError(t, err)

	assert.Equal(t, server.URL+"/oauth/authorize", resolved.authorizationURL)
	assert.Equal(t, server.URL+"/oauth/token", resolved.tokenURL)
	assert.Equal(t, server.URL+"/register", resolved.registrationURL)
	assert.Equal(t, []string{"ZohoMCP.tool.execute", "ZohoMCP.tool.read"}, resolved.scopes)
	assert.Empty(t, resolved.clientID)
}

func TestResolveOAuthConfigWins(t *testing.T) {
	tests := []struct {
		name   string
		auth   config.UserAuthentication
		assert func(t *testing.T, server *httptest.Server, resolved *resolvedOAuth)
	}{
		{
			name: "authorizationUrl",
			auth: config.UserAuthentication{AuthorizationURL: "https://configured.example.com/authorize"},
			assert: func(t *testing.T, server *httptest.Server, resolved *resolvedOAuth) {
				assert.Equal(t, "https://configured.example.com/authorize", resolved.authorizationURL)
				assert.Equal(t, server.URL+"/oauth/token", resolved.tokenURL)
			},
		},
		{
			name: "tokenUrl",
			auth: config.UserAuthentication{TokenURL: "https://configured.example.com/token"},
			assert: func(t *testing.T, server *httptest.Server, resolved *resolvedOAuth) {
				assert.Equal(t, "https://configured.example.com/token", resolved.tokenURL)
				assert.Equal(t, server.URL+"/oauth/authorize", resolved.authorizationURL)
			},
		},
		{
			name: "scopes",
			auth: config.UserAuthentication{Scopes: []string{"read", "write"}},
			assert: func(t *testing.T, server *httptest.Server, resolved *resolvedOAuth) {
				assert.Equal(t, []string{"read", "write"}, resolved.scopes)
			},
		},
		{
			name: "clientId and clientSecret",
			auth: config.UserAuthentication{ClientID: config.Secret("configured-id"), ClientSecret: config.Secret("configured-secret")},
			assert: func(t *testing.T, server *httptest.Server, resolved *resolvedOAuth) {
				assert.Equal(t, "configured-id", resolved.clientID)
				assert.Equal(t, "configured-secret", resolved.clientSecret)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			server := b.start(t)
			client := serviceOAuthTestClient(t)

			auth := tt.auth
			auth.Type = config.UserAuthTypeOAuth
			auth.DisplayName = "Some Server"

			resolved, err := client.resolveOAuth(context.Background(), "someserver", discoverableServer(b.resourceURL(server), &auth))
			require.NoError(t, err)
			tt.assert(t, server, resolved)
		})
	}
}

func TestResolveOAuthSkipsDiscoveryWhenFullyConfigured(t *testing.T) {
	b := &backend{}
	server := b.start(t)
	client := serviceOAuthTestClient(t)

	resolved, err := client.resolveOAuth(context.Background(), "someserver", discoverableServer(b.resourceURL(server), &config.UserAuthentication{
		Type:             config.UserAuthTypeOAuth,
		DisplayName:      "Some Server",
		ClientID:         config.Secret("configured-id"),
		ClientSecret:     config.Secret("configured-secret"),
		AuthorizationURL: "https://configured.example.com/authorize",
		TokenURL:         "https://configured.example.com/token",
		Scopes:           []string{"read"},
	}))
	require.NoError(t, err)

	assert.False(t, resolved.discovered)
	assert.Empty(t, b.requests, "a fully configured server must not touch the backend")
}

func TestResolveOAuthCachesDiscovery(t *testing.T) {
	b := &backend{}
	server := b.start(t)
	client := serviceOAuthTestClient(t)
	serverConfig := discoverableServer(b.resourceURL(server), &config.UserAuthentication{
		Type:        config.UserAuthTypeOAuth,
		DisplayName: "Some Server",
	})

	_, err := client.resolveOAuth(context.Background(), "someserver", serverConfig)
	require.NoError(t, err)
	afterFirst := len(b.requests)
	require.NotZero(t, afterFirst)

	_, err = client.resolveOAuth(context.Background(), "someserver", serverConfig)
	require.NoError(t, err)
	assert.Equal(t, afterFirst, len(b.requests))
}

func TestResolveOAuthWithoutADiscoverableURL(t *testing.T) {
	client := serviceOAuthTestClient(t)

	_, err := client.resolveOAuth(context.Background(), "stainless", &config.MCPClientConfig{
		TransportType:     config.MCPClientTypeStdio,
		Command:           "stainless",
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:        config.UserAuthTypeOAuth,
			DisplayName: "Stainless",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no discoverable url")
}

// A service that supplies its endpoints but no client credentials keeps working when
// its backend advertises nothing to discover.
func TestResolveOAuthFallsBackWhenEndpointsAreConfigured(t *testing.T) {
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer unreachable.Close()

	client := serviceOAuthTestClient(t)
	resolved, err := client.resolveOAuth(context.Background(), "sentry", discoverableServer(unreachable.URL+"/mcp", &config.UserAuthentication{
		Type:             config.UserAuthTypeOAuth,
		DisplayName:      "Sentry",
		AuthorizationURL: "https://sentry.example.com/oauth/authorize",
		TokenURL:         "https://sentry.example.com/oauth/token",
	}))
	require.NoError(t, err)

	assert.False(t, resolved.discovered)
	assert.Equal(t, "https://sentry.example.com/oauth/authorize", resolved.authorizationURL)
	assert.Equal(t, "https://sentry.example.com/oauth/token", resolved.tokenURL)
}

func TestRegisterClientUsesTheDiscoveredEndpointAndScopes(t *testing.T) {
	var registrationBody map[string]any
	b := &backend{}
	server := b.start(t)

	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&registrationBody))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"client_id": "registered-id", "client_secret": "registered-secret"}`))
	}))
	defer registrar.Close()

	client := serviceOAuthTestClient(t)
	reg, err := client.registerClient(context.Background(), "someserver", &resolvedOAuth{
		authorizationURL: server.URL + "/oauth/authorize",
		tokenURL:         server.URL + "/oauth/token",
		registrationURL:  registrar.URL,
		issuer:           server.URL,
		scopes:           []string{"ZohoMCP.tool.execute"},
		discovered:       true,
	})
	require.NoError(t, err)

	assert.Equal(t, "registered-id", reg.ClientID)
	assert.Equal(t, "ZohoMCP.tool.execute", registrationBody["scope"])
}

func TestRegisterClientWithoutARegistrationEndpoint(t *testing.T) {
	b := &backend{registrationOmitted: true}
	server := b.start(t)
	client := serviceOAuthTestClient(t)

	resolved, err := client.resolveOAuth(context.Background(), "someserver", discoverableServer(b.resourceURL(server), &config.UserAuthentication{
		Type:        config.UserAuthTypeOAuth,
		DisplayName: "Some Server",
	}))
	require.NoError(t, err)

	_, err = client.registerClient(context.Background(), "someserver", resolved)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "advertises no registration_endpoint")
}

func TestStartOAuthFlowFromDiscovery(t *testing.T) {
	b := &backend{}
	server := b.start(t)

	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"client_id": "registered-id"}`))
	}))
	defer registrar.Close()
	b.authServerBody = fmt.Sprintf(`{"issuer": "%s", "authorization_endpoint": "%s/oauth/authorize", "token_endpoint": "%s/oauth/token", "registration_endpoint": "%s"}`,
		server.URL, server.URL, server.URL, registrar.URL)

	client := serviceOAuthTestClient(t)
	authURL, err := client.StartOAuthFlow(context.Background(), "user@example.com", "someserver", "/my/tokens",
		discoverableServer(b.resourceURL(server), &config.UserAuthentication{
			Type:        config.UserAuthTypeOAuth,
			DisplayName: "Some Server",
		}))
	require.NoError(t, err)

	assert.Contains(t, authURL, server.URL+"/oauth/authorize")
	assert.Contains(t, authURL, "client_id=registered-id")
	assert.Contains(t, authURL, "scope=ZohoMCP.tool.execute+ZohoMCP.tool.read")
}
