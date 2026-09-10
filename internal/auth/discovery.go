package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
)

const (
	wellKnownAuthServer = "/.well-known/oauth-authorization-server"

	discoveryChainTimeout = 15 * time.Second

	maxMetadataBytes = 1 << 20

	// A well-formed initialize is what gets past a backend that validates the body
	// before it authenticates; an empty POST comes back 400 with no challenge.
	probeInitialize = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-front","version":"discovery"}}}`
)

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

type authServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// discoveredOAuth is what a backend advertises about its authorization server.
type discoveredOAuth struct {
	Issuer           string
	AuthorizationURL string
	TokenURL         string
	RegistrationURL  string
	Scopes           []string
}

// discoverOAuth reads a backend's authorization server out of its 401 challenge:
// RFC 9728 for the resource metadata, RFC 8414 for the server metadata.
func discoverOAuth(ctx context.Context, hc *http.Client, transport config.MCPClientType, resourceURL string) (*discoveredOAuth, error) {
	challenge, err := probeForChallenge(ctx, hc, transport, resourceURL)
	if err != nil {
		return nil, err
	}

	metadataURL, err := challengeResourceMetadataURL(challenge)
	if err != nil {
		return nil, err
	}

	var resource protectedResourceMetadata
	if err := getMetadata(ctx, hc, metadataURL, &resource); err != nil {
		return nil, fmt.Errorf("protected resource metadata %s: %w", metadataURL, err)
	}
	if len(resource.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("protected resource metadata %s lists no authorization_servers", metadataURL)
	}

	issuer := resource.AuthorizationServers[0]
	meta, err := fetchAuthServerMetadata(ctx, hc, issuer)
	if err != nil {
		return nil, err
	}

	return &discoveredOAuth{
		Issuer:           issuer,
		AuthorizationURL: meta.AuthorizationEndpoint,
		TokenURL:         meta.TokenEndpoint,
		RegistrationURL:  meta.RegistrationEndpoint,
		Scopes:           resource.ScopesSupported,
	}, nil
}

func probeForChallenge(ctx context.Context, hc *http.Client, transport config.MCPClientType, resourceURL string) (string, error) {
	req, err := newProbeRequest(ctx, transport, resourceURL)
	if err != nil {
		return "", err
	}

	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("challenging %s: %w", resourceURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMetadataBytes))

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("challenging %s: status %d, want 401 with a WWW-Authenticate challenge", resourceURL, resp.StatusCode)
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	if challenge == "" {
		return "", fmt.Errorf("challenging %s: 401 carried no WWW-Authenticate header", resourceURL)
	}
	return challenge, nil
}

// The server's configured headers carry the user's token template, so the probe
// sends none of them.
func newProbeRequest(ctx context.Context, transport config.MCPClientType, resourceURL string) (*http.Request, error) {
	if transport == config.MCPClientTypeSSE {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
		if err != nil {
			return nil, fmt.Errorf("challenging %s: %w", resourceURL, err)
		}
		req.Header.Set("Accept", "text/event-stream")
		return req, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceURL, strings.NewReader(probeInitialize))
	if err != nil {
		return nil, fmt.Errorf("challenging %s: %w", resourceURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	return req, nil
}

var resourceMetadataParam = regexp.MustCompile(`resource_metadata\s*=\s*(?:"([^"]*)"|([^,\s]+))`)

func challengeResourceMetadataURL(challenge string) (string, error) {
	match := resourceMetadataParam.FindStringSubmatch(challenge)
	if match == nil {
		return "", fmt.Errorf("WWW-Authenticate challenge %q has no resource_metadata parameter", challenge)
	}
	value := match[1]
	if value == "" {
		value = match[2]
	}
	if value == "" {
		return "", fmt.Errorf("WWW-Authenticate challenge %q has an empty resource_metadata parameter", challenge)
	}
	return value, nil
}

// Rejecting a document that names a different issuer (RFC 8414 section 3.3) is what
// stops a resource from retargeting the flow at an authorization server of its own
// choosing.
func fetchAuthServerMetadata(ctx context.Context, hc *http.Client, issuer string) (*authServerMetadata, error) {
	candidates, err := wellKnownCandidates(issuer)
	if err != nil {
		return nil, err
	}

	attempts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		var meta authServerMetadata
		if err := getMetadata(ctx, hc, candidate, &meta); err != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		if !sameIssuer(meta.Issuer, issuer) {
			attempts = append(attempts, fmt.Sprintf("%s: issuer is %q, want %q", candidate, meta.Issuer, issuer))
			continue
		}
		return &meta, nil
	}

	return nil, fmt.Errorf("authorization server metadata for issuer %s: %s", issuer, strings.Join(attempts, "; "))
}

func wellKnownCandidates(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer %q is not a URL: %w", issuer, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}

	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")
	if path == "" {
		return []string{origin + wellKnownAuthServer}, nil
	}
	return []string{
		origin + wellKnownAuthServer + path,
		origin + path + wellKnownAuthServer,
		origin + wellKnownAuthServer,
	}, nil
}

func sameIssuer(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func getMetadata(ctx context.Context, hc *http.Client, metadataURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMetadataBytes))
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetadataBytes)).Decode(out); err != nil {
		return fmt.Errorf("decoding: %w", err)
	}
	return nil
}
