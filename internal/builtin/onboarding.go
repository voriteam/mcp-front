package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/log"
)

const (
	tinyURLCreateEndpoint = "https://api.tinyurl.com/create"

	// Must match InvitationType.Signing in backend
	// shared/nest/libs/invitations/enum.ts.
	invitationTypeSigning = "signing"

	// A link is a bearer credential; the ceiling turns a mistyped expiry into a
	// tool error rather than a year-long invitation.
	maxOnboardingTTLDays = 90
)

type OnboardingConfig struct {
	// Secret Manager: invitation-signing-secret. The same secret the backend's
	// InvitationTokensService verifies with.
	SigningKey      []byte
	DefaultTokenTTL time.Duration // used when the caller names no expiry; backend default is 7 days
	AppRootURL      string        // backend config app_root_url; link is <root>/welcome
	Issuer          string        // matches VORI_JWT_ISSUER in backend shared/providers/jwt_handler.ts
	TinyURLAPIKey   string        // Secret Manager: tinyurl-api-key
	ShortenerDomain string        // matches backend config url_shortener.domain
	ShortenerTags   []string      // e.g. ["gtm-onboarding"] — this is the tracking hook
	HTTPClient      *http.Client

	// endpoint overrides tinyURLCreateEndpoint so tests can serve it locally.
	endpoint string
}

type onboardingArgs struct {
	HubspotDealID  string `json:"hubspotDealId"`
	RecipientEmail string `json:"recipientEmail"`
	// Absent means fall back to DefaultTokenTTL; a pointer keeps that
	// distinguishable from an explicit zero, which is an error.
	ExpiresInDays *int `json:"expiresInDays,omitempty"`
}

const onboardingSchemaFormat = `{
  "type": "object",
  "properties": {
    "hubspotDealId":  {"type": "string", "description": "HubSpot deal the onboarding link is for."},
    "recipientEmail": {"type": "string", "description": "Address that will receive the link and complete signup."},
    "expiresInDays":  {"type": "integer", "minimum": 1, "maximum": %d, "description": "How long the link stays valid. Defaults to %d days."}
  },
  "required": ["hubspotDealId", "recipientEmail"],
  "additionalProperties": false
}`

const onboardingOutputSchema = `{
  "type": "object",
  "properties": {
    "url":       {"type": "string", "format": "uri", "description": "Short onboarding link to send to the recipient."},
    "expiresAt": {"type": "string", "format": "date-time", "description": "When the link stops working, RFC 3339 in UTC."}
  },
  "required": ["url", "expiresAt"],
  "additionalProperties": false
}`

type onboardingLink struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
}

// OnboardingTools returns an error naming every field left empty. A blank
// signing key would otherwise mint links that look right and fail only when
// their recipient redeems them.
func OnboardingTools(cfg OnboardingConfig) ([]Tool, error) {
	var missing []string
	if len(cfg.SigningKey) == 0 {
		missing = append(missing, "signing key")
	}
	if cfg.AppRootURL == "" {
		missing = append(missing, "app root URL")
	}
	if cfg.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if cfg.TinyURLAPIKey == "" {
		missing = append(missing, "shortener API key")
	}
	if cfg.ShortenerDomain == "" {
		missing = append(missing, "shortener domain")
	}
	if cfg.DefaultTokenTTL <= 0 {
		missing = append(missing, "default TTL")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("onboarding builtin is missing: %s", strings.Join(missing, ", "))
	}

	return []Tool{{
		Name:        "create_onboarding_link",
		Description: "Generate a short onboarding URL for a HubSpot deal, to be sent to the named recipient. Returns the link and the moment it expires.",
		InputSchema: json.RawMessage(fmt.Sprintf(onboardingSchemaFormat,
			maxOnboardingTTLDays, int(cfg.DefaultTokenTTL/(24*time.Hour)))),
		OutputSchema: json.RawMessage(onboardingOutputSchema),
		Handler:      cfg.createLink,
	}}, nil
}

func (cfg OnboardingConfig) createLink(ctx context.Context, userEmail string, raw json.RawMessage) (*mcp.CallToolResult, error) {
	var args onboardingArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.HubspotDealID == "" || args.RecipientEmail == "" {
		return mcp.NewToolResultError("hubspotDealId and recipientEmail are both required"), nil
	}

	ttl := cfg.DefaultTokenTTL
	if args.ExpiresInDays != nil {
		days := *args.ExpiresInDays
		if days < 1 || days > maxOnboardingTTLDays {
			return mcp.NewToolResultError(fmt.Sprintf("expiresInDays must be between 1 and %d", maxOnboardingTTLDays)), nil
		}
		ttl = time.Duration(days) * 24 * time.Hour
	}

	now := time.Now()
	expires := now.Add(ttl)
	expiresAt := expires.UTC().Format(time.RFC3339)

	// Claim names are fixed by the backend's InvitationTokensService.verify:
	// anything else is rejected as InvalidInvitationTokenError.
	signed, err := crypto.SignHS256(cfg.SigningKey, map[string]any{
		"invitation_type": invitationTypeSigning,
		"hubspot_deal_id": args.HubspotDealID,
		"email":           args.RecipientEmail,
		"iss":             cfg.Issuer,
		"iat":             now.Unix(),
		"exp":             expires.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("signing invitation token: %w", err)
	}

	long := cfg.AppRootURL + "/welcome?token=" + url.QueryEscape(signed)
	short, err := cfg.shorten(ctx, long)
	if err != nil {
		return nil, fmt.Errorf("shortening onboarding url: %w", err)
	}

	log.LogInfoWithFields("builtin", "Onboarding link issued", map[string]any{
		"issuedBy":  userEmail,
		"dealId":    args.HubspotDealID,
		"recipient": args.RecipientEmail,
		"expiresAt": expiresAt,
	})

	return mcp.NewToolResultJSON(onboardingLink{URL: short, ExpiresAt: expiresAt})
}

func (cfg OnboardingConfig) shorten(ctx context.Context, long string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"url":    long,
		"domain": cfg.ShortenerDomain,
		"tags":   strings.Join(cfg.ShortenerTags, ","),
	})
	if err != nil {
		return "", err
	}
	endpoint := cfg.endpoint
	if endpoint == "" {
		endpoint = tinyURLCreateEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.TinyURLAPIKey)

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("tinyurl returned %d", resp.StatusCode)
	}

	var out struct {
		Data struct {
			TinyURL string `json:"tiny_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Data.TinyURL == "" {
		return "", fmt.Errorf("tinyurl returned no tiny_url")
	}
	return out.Data.TinyURL, nil
}
