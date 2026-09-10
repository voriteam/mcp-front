package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// backend serves the documents an OAuth-protected MCP server advertises, in the
// shapes measured against a live vendor deployment.
type backend struct {
	resourcePath string

	challenge           string
	omitChallenge       bool
	resourceStatus      int
	resourceBody        string
	wellKnownPath       string
	authServerStatus    int
	authServerBody      string
	authServerIssuer    string
	registrationOmitted bool

	requests []string
}

func (b *backend) start(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resourcePath := b.resourcePath
	if resourcePath == "" {
		resourcePath = "/mcp/abc123/message"
	}
	wellKnownPath := b.wellKnownPath
	if wellKnownPath == "" {
		wellKnownPath = wellKnownAuthServer
	}
	issuer := b.authServerIssuer
	if issuer == "" {
		issuer = server.URL
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b.requests = append(b.requests, r.Method+" "+r.URL.Path)
		http.NotFound(w, r)
	})

	mux.HandleFunc(resourcePath, func(w http.ResponseWriter, r *http.Request) {
		b.requests = append(b.requests, r.Method+" "+r.URL.Path)
		if !b.omitChallenge {
			challenge := b.challenge
			if challenge == "" {
				challenge = fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, server.URL)
			}
			w.Header().Set("WWW-Authenticate", challenge)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		b.requests = append(b.requests, r.Method+" "+r.URL.Path)
		if b.resourceStatus != 0 && b.resourceStatus != http.StatusOK {
			w.WriteHeader(b.resourceStatus)
			return
		}
		body := b.resourceBody
		if body == "" {
			body = fmt.Sprintf(`{
				"resource": "%s%s",
				"authorization_servers": ["%s"],
				"scopes_supported": ["ZohoMCP.tool.execute", "ZohoMCP.tool.read"]
			}`, server.URL, resourcePath, issuer)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	mux.HandleFunc(wellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		b.requests = append(b.requests, r.Method+" "+r.URL.Path)
		if b.authServerStatus != 0 && b.authServerStatus != http.StatusOK {
			w.WriteHeader(b.authServerStatus)
			return
		}
		body := b.authServerBody
		if body == "" {
			registration := fmt.Sprintf(`"registration_endpoint": "%s/register",`, server.URL)
			if b.registrationOmitted {
				registration = ""
			}
			body = fmt.Sprintf(`{
				"issuer": "%s",
				"authorization_endpoint": "%s/oauth/authorize",
				"token_endpoint": "%s/oauth/token",
				%s
				"code_challenge_methods_supported": ["S256"],
				"grant_types_supported": ["authorization_code", "refresh_token"],
				"token_endpoint_auth_methods_supported": ["none", "client_secret_post"]
			}`, issuer, server.URL, server.URL, registration)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	return server
}

func (b *backend) resourceURL(server *httptest.Server) string {
	if b.resourcePath == "" {
		return server.URL + "/mcp/abc123/message"
	}
	return server.URL + b.resourcePath
}

func TestDiscoverOAuth(t *testing.T) {
	t.Run("reads the endpoints from a 401 challenge", func(t *testing.T) {
		b := &backend{}
		server := b.start(t)

		discovered, err := discoverOAuth(context.Background(), server.Client(), config.MCPClientTypeStreamable, b.resourceURL(server))
		require.NoError(t, err)

		assert.Equal(t, server.URL, discovered.Issuer)
		assert.Equal(t, server.URL+"/oauth/authorize", discovered.AuthorizationURL)
		assert.Equal(t, server.URL+"/oauth/token", discovered.TokenURL)
		assert.Equal(t, server.URL+"/register", discovered.RegistrationURL)
		assert.Equal(t, []string{"ZohoMCP.tool.execute", "ZohoMCP.tool.read"}, discovered.Scopes)
		assert.Contains(t, b.requests, "POST /mcp/abc123/message")
	})

	t.Run("probes an sse backend with GET", func(t *testing.T) {
		b := &backend{resourcePath: "/sse"}
		server := b.start(t)

		_, err := discoverOAuth(context.Background(), server.Client(), config.MCPClientTypeSSE, b.resourceURL(server))
		require.NoError(t, err)
		assert.Contains(t, b.requests, "GET /sse")
	})

	t.Run("carries no credentials into the probe", func(t *testing.T) {
		var probeAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			probeAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		_, err := discoverOAuth(context.Background(), server.Client(), config.MCPClientTypeStreamable, server.URL+"/message")
		require.Error(t, err)
		assert.Empty(t, probeAuth)
	})
}

func TestDiscoverOAuthFailures(t *testing.T) {
	tests := []struct {
		name        string
		backend     *backend
		expectError string
	}{
		{
			name:        "401 without a challenge",
			backend:     &backend{omitChallenge: true},
			expectError: "401 carried no WWW-Authenticate header",
		},
		{
			name:        "challenge without a resource_metadata parameter",
			backend:     &backend{challenge: `Bearer realm="mcp", error="invalid_token"`},
			expectError: "has no resource_metadata parameter",
		},
		{
			name:        "resource metadata is missing",
			backend:     &backend{resourceStatus: http.StatusNotFound},
			expectError: "protected resource metadata",
		},
		{
			name:        "resource metadata names no authorization server",
			backend:     &backend{resourceBody: `{"resource": "https://example.com", "authorization_servers": []}`},
			expectError: "lists no authorization_servers",
		},
		{
			name:        "authorization server metadata is rejected",
			backend:     &backend{authServerStatus: http.StatusBadRequest},
			expectError: "status 400",
		},
		{
			name:        "authorization server metadata names a different issuer",
			backend:     &backend{authServerBody: `{"issuer": "https://somewhere.else.example.com"}`},
			expectError: "issuer is",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.backend.start(t)

			_, err := discoverOAuth(context.Background(), server.Client(), config.MCPClientTypeStreamable, tt.backend.resourceURL(server))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestDiscoverOAuthWhenTheResourceStatusIsWrong(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := discoverOAuth(context.Background(), server.Client(), config.MCPClientTypeStreamable, server.URL+"/message")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 200, want 401")
}

func TestChallengeResourceMetadataURL(t *testing.T) {
	tests := []struct {
		name        string
		challenge   string
		expectURL   string
		expectError string
	}{
		{
			name:      "quoted parameter",
			challenge: `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			expectURL: "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:      "after other parameters",
			challenge: `Bearer realm="mcp", error="invalid_token", resource_metadata="https://example.com/prm"`,
			expectURL: "https://example.com/prm",
		},
		{
			name:      "unquoted parameter",
			challenge: `Bearer resource_metadata=https://example.com/prm`,
			expectURL: "https://example.com/prm",
		},
		{
			name:        "absent",
			challenge:   `Bearer realm="mcp"`,
			expectError: "no resource_metadata parameter",
		},
		{
			name:        "empty",
			challenge:   `Bearer resource_metadata=""`,
			expectError: "empty resource_metadata parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := challengeResourceMetadataURL(tt.challenge)
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectURL, got)
		})
	}
}

func TestWellKnownCandidates(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		expect      []string
		expectError string
	}{
		{
			name:   "a pathless issuer has only the root form",
			issuer: "https://auth.example.com",
			expect: []string{"https://auth.example.com/.well-known/oauth-authorization-server"},
		},
		{
			name:   "an issuer with a path tries the path-inserted form first",
			issuer: "https://auth.example.com/tenant/7",
			expect: []string{
				"https://auth.example.com/.well-known/oauth-authorization-server/tenant/7",
				"https://auth.example.com/tenant/7/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/oauth-authorization-server",
			},
		},
		{
			name:        "a relative issuer is rejected",
			issuer:      "auth.example.com",
			expectError: "not an absolute URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := wellKnownCandidates(tt.issuer)
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func TestFetchAuthServerMetadataPathInsertedForm(t *testing.T) {
	var served []string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		served = append(served, r.URL.Path)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/tenant/7", func(w http.ResponseWriter, r *http.Request) {
		served = append(served, r.URL.Path)
		fmt.Fprintf(w, `{"issuer": "%s/tenant/7", "authorization_endpoint": "%s/authorize", "token_endpoint": "%s/token"}`, server.URL, server.URL, server.URL)
	})

	meta, err := fetchAuthServerMetadata(context.Background(), server.Client(), server.URL+"/tenant/7")
	require.NoError(t, err)
	assert.Equal(t, server.URL+"/authorize", meta.AuthorizationEndpoint)
	assert.Equal(t, []string{"/.well-known/oauth-authorization-server/tenant/7"}, served)
}

// TestDiscoverOAuthAcrossHosts is the regression: the issuer serves the metadata, and
// the authorization endpoint it names lives on a host that serves the well-known path
// a 400. Deriving the metadata URL from the authorization endpoint fails outright.
func TestDiscoverOAuthAcrossHosts(t *testing.T) {
	var authHostWellKnownHits int
	authHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			authHostWellKnownHits++
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authHost.Close()

	issuerMux := http.NewServeMux()
	issuerHost := httptest.NewServer(issuerMux)
	defer issuerHost.Close()

	issuerMux.HandleFunc("/mcp/abc123/message", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, issuerHost.URL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	issuerMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"resource": "%s/mcp/abc123/message", "authorization_servers": ["%s"], "scopes_supported": ["tool.execute"]}`, issuerHost.URL, issuerHost.URL)
	})
	issuerMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer": "%s", "authorization_endpoint": "%s/oauth/authorize", "token_endpoint": "%s/oauth/token", "registration_endpoint": "%s/register"}`,
			issuerHost.URL, authHost.URL, authHost.URL, authHost.URL)
	})

	discovered, err := discoverOAuth(context.Background(), issuerHost.Client(), config.MCPClientTypeStreamable, issuerHost.URL+"/mcp/abc123/message")
	require.NoError(t, err)

	assert.Equal(t, issuerHost.URL, discovered.Issuer)
	assert.Equal(t, authHost.URL+"/oauth/authorize", discovered.AuthorizationURL)
	assert.Equal(t, authHost.URL+"/register", discovered.RegistrationURL)
	assert.Zero(t, authHostWellKnownHits, "metadata must be read from the issuer, not the authorization endpoint's host")
}
