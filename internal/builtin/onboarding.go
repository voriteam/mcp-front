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

	// Must match VORI_JWT_ISSUER in backend shared/providers/jwt_handler.ts.
	voriJWTIssuer = "https://jwt.vori.com"

	// Must match InvitationType.Signing in backend
	// shared/nest/libs/invitations/enum.ts.
	invitationTypeSigning = "signing"
)

type OnboardingConfig struct {
	// Secret Manager: invitation-signing-secret. The same secret the backend's
	// InvitationTokensService verifies with.
	SigningKey      []byte
	TokenTTL        time.Duration // backend default is 7 days
	AppRootURL      string        // backend config app_root_url; link is <root>/welcome
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
}

const onboardingSchema = `{
  "type": "object",
  "properties": {
    "hubspotDealId":  {"type": "string", "description": "HubSpot deal the onboarding link is for."},
    "recipientEmail": {"type": "string", "description": "Address that will receive the link and complete signup."}
  },
  "required": ["hubspotDealId", "recipientEmail"],
  "additionalProperties": false
}`

func OnboardingTools(cfg OnboardingConfig) []Tool {
	return []Tool{{
		Name:        "create_onboarding_link",
		Description: "Generate a short onboarding URL for a HubSpot deal, to be sent to the named recipient.",
		InputSchema: json.RawMessage(onboardingSchema),
		Handler:     cfg.createLink,
	}}
}

func (cfg OnboardingConfig) createLink(ctx context.Context, userEmail string, raw json.RawMessage) (*mcp.CallToolResult, error) {
	var args onboardingArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.HubspotDealID == "" || args.RecipientEmail == "" {
		return mcp.NewToolResultError("hubspotDealId and recipientEmail are both required"), nil
	}

	now := time.Now()
	expires := now.Add(cfg.TokenTTL)

	// Claim names are fixed by the backend's InvitationTokensService.verify:
	// anything else is rejected as InvalidInvitationTokenError.
	signed, err := crypto.SignHS256(cfg.SigningKey, map[string]any{
		"invitation_type": invitationTypeSigning,
		"hubspot_deal_id": args.HubspotDealID,
		"email":           args.RecipientEmail,
		"iss":             voriJWTIssuer,
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
		"expiresAt": expires.UTC().Format(time.RFC3339),
	})

	return mcp.NewToolResultText(short), nil
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
