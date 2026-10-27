package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/stainless-api/mcp-front/internal/log"
)

const (
	defaultTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	maxCacheTTL         = 5 * time.Minute
)

// GCPProviderType marks identities issued through the token-exchange grant.
const GCPProviderType = "gcp"

type cachedTokenInfo struct {
	email     string
	expiresAt time.Time
}

type GCPAccessTokenValidatorConfig struct {
	TokenInfoURL string
	// Roles is required when CallerRole is set.
	Roles            RoleChecker
	CallerRole       string
	ImpersonatorRole string
}

type GCPAccessTokenValidator struct {
	tokenInfoURL     string
	roles            RoleChecker
	callerRole       string
	impersonatorRole string
	httpClient       *http.Client
	cache            sync.Map
}

func NewGCPAccessTokenValidator(cfg GCPAccessTokenValidatorConfig) *GCPAccessTokenValidator {
	tokenInfoURL := cfg.TokenInfoURL
	if tokenInfoURL == "" {
		tokenInfoURL = defaultTokenInfoURL
	}
	return &GCPAccessTokenValidator{
		tokenInfoURL:     tokenInfoURL,
		roles:            cfg.Roles,
		callerRole:       cfg.CallerRole,
		impersonatorRole: cfg.ImpersonatorRole,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}
}

// IsAllowed reports whether the service account holds the caller role. It is
// checked on every request, so removing the binding takes effect within the
// IAM policy cache's lifetime.
func (v *GCPAccessTokenValidator) IsAllowed(ctx context.Context, email string) (bool, error) {
	return v.hasRole(ctx, v.callerRole, email)
}

func (v *GCPAccessTokenValidator) CanImpersonate(ctx context.Context, email string) (bool, error) {
	return v.hasRole(ctx, v.impersonatorRole, email)
}

func (v *GCPAccessTokenValidator) hasRole(ctx context.Context, role, email string) (bool, error) {
	if role == "" || v.roles == nil {
		return false, nil
	}
	return v.roles.HasRole(ctx, role, email)
}

func (v *GCPAccessTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	email, err := v.tokenEmail(ctx, token)
	if err != nil {
		return "", err
	}

	allowed, err := v.IsAllowed(ctx, email)
	if err != nil {
		log.LogErrorWithFields("gcp_auth", "Could not check the service account's IAM role", map[string]any{
			"email": email,
			"error": err.Error(),
		})
		return "", fmt.Errorf("checking service account access failed")
	}
	if !allowed {
		log.LogWarnWithFields("gcp_auth", "Rejected access token from an account without the caller role", map[string]any{
			"email": email,
			"role":  v.callerRole,
		})
		return "", fmt.Errorf("GCP account is not an allowed service account")
	}
	return email, nil
}

func (v *GCPAccessTokenValidator) tokenEmail(ctx context.Context, token string) (string, error) {
	if cached, ok := v.cache.Load(token); ok {
		info := cached.(*cachedTokenInfo)
		if time.Now().Before(info.expiresAt) {
			return info.email, nil
		}
		v.cache.Delete(token)
	}

	reqURL := v.tokenInfoURL + "?access_token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating tokeninfo request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("tokeninfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP access token validation failed: status %d", resp.StatusCode)
	}

	var result struct {
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		ExpiresIn     string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing tokeninfo response: %w", err)
	}

	if result.Email == "" {
		return "", fmt.Errorf("GCP access token missing email claim")
	}

	if result.EmailVerified != "true" {
		return "", fmt.Errorf("GCP access token email not verified")
	}

	ttl := maxCacheTTL
	if result.ExpiresIn != "" {
		if expiresInSec, err := strconv.Atoi(result.ExpiresIn); err == nil {
			tokenTTL := time.Duration(expiresInSec) * time.Second
			if tokenTTL < ttl {
				ttl = tokenTTL
			}
		}
	}

	v.cache.Store(token, &cachedTokenInfo{
		email:     result.Email,
		expiresAt: time.Now().Add(ttl),
	})

	log.LogDebugWithFields("gcp_auth", "Access token validated and cached", map[string]any{
		"email": result.Email,
		"ttl":   ttl.String(),
	})

	return result.Email, nil
}
