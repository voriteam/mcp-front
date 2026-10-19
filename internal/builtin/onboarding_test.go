package builtin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// Pins the exact claim set rather than a subset, so a stray claim fails here
// instead of surprising the backend's InvitationTokensService.verify.
func TestCreateLink_TokenShape(t *testing.T) {
	baseClaims := []string{"invitation_type", "hubspot_deal_id", "email", "iss", "iat", "exp"}
	cases := []struct {
		name           string
		args           string
		invitationType string
		wantClaims     []string
		contactID      any
	}{
		{
			name:           "signing without a contact",
			args:           `{"invitationType":"signing","hubspotDealId":"12345","recipientEmail":"buyer@grocer.example"}`,
			invitationType: "signing",
			wantClaims:     baseClaims,
		},
		{
			name:           "signing with a contact",
			args:           `{"invitationType":"signing","hubspotDealId":"12345","recipientEmail":"buyer@grocer.example","hubspotContactId":"67890"}`,
			invitationType: "signing",
			wantClaims:     append(append([]string{}, baseClaims...), "hubspot_contact_id"),
			contactID:      "67890",
		},
		{
			name:           "merchant processing agreement without a contact",
			args:           `{"invitationType":"merchant_processing_agreement","hubspotDealId":"12345","recipientEmail":"buyer@grocer.example"}`,
			invitationType: "merchant_processing_agreement",
			wantClaims:     baseClaims,
		},
		{
			name:           "merchant processing agreement with a contact",
			args:           `{"invitationType":"merchant_processing_agreement","hubspotDealId":"12345","recipientEmail":"buyer@grocer.example","hubspotContactId":"67890"}`,
			invitationType: "merchant_processing_agreement",
			wantClaims:     append(append([]string{}, baseClaims...), "hubspot_contact_id"),
			contactID:      "67890",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, long := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
			res, err := tool.Handler(context.Background(), "ae@vori.com", json.RawMessage(tc.args))
			require.NoError(t, err)
			require.NotNil(t, res)

			parsed, err := url.Parse(*long)
			require.NoError(t, err)
			assert.Equal(t, "https", parsed.Scheme)
			assert.Equal(t, "app.vori.com", parsed.Host)
			assert.Equal(t, "/welcome", parsed.Path)

			claims := claimsFromLink(t, *long)
			assert.Equal(t, tc.invitationType, claims["invitation_type"])
			assert.Equal(t, "12345", claims["hubspot_deal_id"])
			assert.Equal(t, "buyer@grocer.example", claims["email"])
			assert.Equal(t, "https://jwt.vori.com", claims["iss"])
			assert.Equal(t, tc.contactID, claims["hubspot_contact_id"])

			assert.ElementsMatch(t, tc.wantClaims, keysOf(claims), "claim set must be exactly this")

			iat, ok := claims["iat"].(float64)
			require.True(t, ok)
			exp, ok := claims["exp"].(float64)
			require.True(t, ok)
			assert.Equal(t, float64(7*24*time.Hour/time.Second), exp-iat)

			link := linkResult(t, res)
			assert.Equal(t, "https://link.vori.io/abc123", link.URL)
			assertExpiresAtMatchesToken(t, link, claims)
		})
	}
}

func TestOnboardingSchema_ContactIsOptional(t *testing.T) {
	tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})

	var schema struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	require.NoError(t, json.Unmarshal(tool.InputSchema, &schema))

	require.Contains(t, schema.Properties, "hubspotContactId")
	assert.Equal(t, "string", schema.Properties["hubspotContactId"].Type)
	assert.NotContains(t, schema.Required, "hubspotContactId")
}

func TestOnboardingSchema_InvitationTypeIsRequiredEnum(t *testing.T) {
	tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})

	var schema struct {
		Properties map[string]struct {
			Type    string   `json:"type"`
			Enum    []string `json:"enum"`
			Default any      `json:"default"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	require.NoError(t, json.Unmarshal(tool.InputSchema, &schema))

	require.Contains(t, schema.Properties, "invitationType")
	prop := schema.Properties["invitationType"]
	assert.Equal(t, "string", prop.Type)
	assert.Nil(t, prop.Default)
	assert.Contains(t, schema.Required, "invitationType")

	want := make([]string, 0, len(invitationTypes))
	for it := range invitationTypes {
		want = append(want, string(it))
	}
	assert.ElementsMatch(t, want, prop.Enum, "the schema enum must match the accepted invitation types")
}

// Clients read either the structured content or the text block, so the two
// must carry the same object.
func linkResult(t *testing.T, res *mcp.CallToolResult) onboardingLink {
	t.Helper()
	require.NotNil(t, res)
	require.False(t, res.IsError)

	link, ok := res.StructuredContent.(onboardingLink)
	require.True(t, ok, "structured content is %T", res.StructuredContent)

	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok, "content is %T", res.Content[0])

	var fromText map[string]any
	require.NoError(t, json.Unmarshal([]byte(text.Text), &fromText))
	raw, err := json.Marshal(link)
	require.NoError(t, err)
	var fromStructured map[string]any
	require.NoError(t, json.Unmarshal(raw, &fromStructured))
	assert.Equal(t, fromStructured, fromText)
	assert.ElementsMatch(t, []string{"url", "expiresAt"}, keysOf(fromText))
	return link
}

func assertExpiresAtMatchesToken(t *testing.T, link onboardingLink, claims map[string]any) {
	t.Helper()
	assert.True(t, strings.HasSuffix(link.ExpiresAt, "Z"), "expiresAt %q must be UTC", link.ExpiresAt)
	expiresAt, err := time.Parse(time.RFC3339, link.ExpiresAt)
	require.NoError(t, err)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	assert.Equal(t, int64(exp), expiresAt.Unix())
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// newLinkTool returns the tool plus a pointer to the long URL the shortener saw.
func newLinkTool(t *testing.T, cfg OnboardingConfig) (Tool, *string) {
	t.Helper()
	long := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		*long = body["url"]
		_, _ = io.WriteString(w, `{"data":{"tiny_url":"https://link.vori.io/abc123"}}`)
	}))
	t.Cleanup(srv.Close)

	cfg.HTTPClient = srv.Client()
	cfg.endpoint = srv.URL
	if cfg.SigningKey == nil {
		cfg.SigningKey = []byte("invitation-signing-secret-value-32b")
	}
	if cfg.AppRootURL == "" {
		cfg.AppRootURL = "https://app.vori.com"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "https://jwt.vori.com"
	}
	if cfg.TinyURLAPIKey == "" {
		cfg.TinyURLAPIKey = "tinyurl-key"
	}
	if cfg.ShortenerDomain == "" {
		cfg.ShortenerDomain = "link.vori.io"
	}
	tools, err := OnboardingTools(cfg)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	return tools[0], long
}

func claimsFromLink(t *testing.T, long string) map[string]any {
	t.Helper()
	parsed, err := url.Parse(long)
	require.NoError(t, err)
	token := parsed.Query().Get("token")
	require.NotEmpty(t, token)
	return decodeClaims(t, token)
}

func TestCreateLink_ExpiryInDays(t *testing.T) {
	t.Run("defaults when the caller names none", func(t *testing.T) {
		tool, long := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
		res, err := tool.Handler(context.Background(), "ae@vori.com",
			json.RawMessage(`{"invitationType":"signing","hubspotDealId":"1","recipientEmail":"b@g.example"}`))
		require.NoError(t, err)

		claims := claimsFromLink(t, *long)
		assert.Equal(t, float64(7*24*60*60), claims["exp"].(float64)-claims["iat"].(float64))
		assertExpiresAtMatchesToken(t, linkResult(t, res), claims)
	})

	t.Run("honours a caller-supplied expiry", func(t *testing.T) {
		tool, long := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
		res, err := tool.Handler(context.Background(), "ae@vori.com",
			json.RawMessage(`{"invitationType":"signing","hubspotDealId":"1","recipientEmail":"b@g.example","expiresInDays":14}`))
		require.NoError(t, err)

		claims := claimsFromLink(t, *long)
		assert.Equal(t, float64(14*24*60*60), claims["exp"].(float64)-claims["iat"].(float64))
		assertExpiresAtMatchesToken(t, linkResult(t, res), claims)
	})

	t.Run("rejects out-of-range expiries", func(t *testing.T) {
		tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
		for _, days := range []string{"0", "-1", "91"} {
			res, err := tool.Handler(context.Background(), "ae@vori.com",
				json.RawMessage(`{"invitationType":"signing","hubspotDealId":"1","recipientEmail":"b@g.example","expiresInDays":`+days+`}`))
			require.NoError(t, err, "a bad expiry is a tool error, not a Go error")
			assert.True(t, res.IsError, "expiresInDays=%s must be rejected", days)
		}
	})
}

func TestOnboardingSchema_AdvertisesDefaultAndCeiling(t *testing.T) {
	tools, err := OnboardingTools(OnboardingConfig{
		SigningKey:      []byte("k"),
		DefaultTokenTTL: 7 * 24 * time.Hour,
		AppRootURL:      "https://app.vori.com",
		Issuer:          "https://jwt.vori.com",
		TinyURLAPIKey:   "tinyurl-key",
		ShortenerDomain: "link.vori.io",
	})
	require.NoError(t, err)

	var schema struct {
		Properties struct {
			ExpiresInDays struct {
				Minimum     int    `json:"minimum"`
				Maximum     int    `json:"maximum"`
				Description string `json:"description"`
			} `json:"expiresInDays"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(tools[0].InputSchema, &schema))

	assert.Equal(t, 1, schema.Properties.ExpiresInDays.Minimum)
	assert.Equal(t, maxOnboardingTTLDays, schema.Properties.ExpiresInDays.Maximum)
	assert.Contains(t, schema.Properties.ExpiresInDays.Description, "7 days",
		"the advertised default must track DefaultTokenTTL")
}

func TestOnboardingSchema_DeclaresOutput(t *testing.T) {
	tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})

	var schema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	require.NoError(t, json.Unmarshal(tool.OutputSchema, &schema))

	assert.Equal(t, "object", schema.Type)
	assert.ElementsMatch(t, []string{"url", "expiresAt"}, schema.Required)
	assert.ElementsMatch(t, []string{"url", "expiresAt"}, keysOf(schema.Properties))
}

func TestCreateLink_RejectsBadArguments(t *testing.T) {
	const invitationTypeErr = "invitationType is required and must be signing or merchant_processing_agreement"
	cases := []struct {
		name    string
		args    string
		wantErr string
	}{
		{"no deal", `{"invitationType":"signing","recipientEmail":"buyer@grocer.example"}`, "hubspotDealId and recipientEmail are both required"},
		{"no email", `{"invitationType":"signing","hubspotDealId":"12345"}`, "hubspotDealId and recipientEmail are both required"},
		{"no invitation type", `{"hubspotDealId":"12345","recipientEmail":"buyer@grocer.example"}`, invitationTypeErr},
		{"unknown invitation type", `{"invitationType":"onboarding","hubspotDealId":"12345","recipientEmail":"buyer@grocer.example"}`, invitationTypeErr},
		{"malformed", `{`, "invalid arguments: unexpected end of JSON input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, long := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
			res, err := tool.Handler(context.Background(), "ae@vori.com", json.RawMessage(tc.args))
			require.NoError(t, err, "bad input is a tool error, not a Go error")
			require.NotNil(t, res)
			assert.True(t, res.IsError)
			require.Len(t, res.Content, 1)
			text, ok := res.Content[0].(mcp.TextContent)
			require.True(t, ok, "content is %T", res.Content[0])
			assert.Equal(t, tc.wantErr, text.Text)
			assert.Empty(t, *long, "no link is minted")
		})
	}
}

func TestShorten_RequestShape(t *testing.T) {
	var gotAuth, gotPath, gotContentType string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_, _ = io.WriteString(w, `{"data":{"tiny_url":"https://link.vori.io/xyz"}}`)
	}))
	defer srv.Close()

	cfg := OnboardingConfig{
		TinyURLAPIKey:   "tinyurl-key",
		ShortenerDomain: "link.vori.io",
		ShortenerTags:   []string{"gtm-onboarding", "signing-invite"},
		HTTPClient:      srv.Client(),
		endpoint:        srv.URL,
	}

	short, err := cfg.shorten(context.Background(), "https://app.vori.com/welcome?token=t")
	require.NoError(t, err)

	assert.Equal(t, "https://link.vori.io/xyz", short)
	assert.Equal(t, "Bearer tinyurl-key", gotAuth)
	assert.Equal(t, "application/json", gotContentType)
	assert.Equal(t, "/", gotPath)
	assert.Equal(t, "https://app.vori.com/welcome?token=t", gotBody["url"])
	assert.Equal(t, "link.vori.io", gotBody["domain"])
	assert.Equal(t, "gtm-onboarding,signing-invite", gotBody["tags"], "tags are comma-joined")
}

func TestShorten_Errors(t *testing.T) {
	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		cfg := OnboardingConfig{HTTPClient: srv.Client(), endpoint: srv.URL}
		_, err := cfg.shorten(context.Background(), "https://app.vori.com/welcome")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("empty tiny_url", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"data":{}}`)
		}))
		defer srv.Close()
		cfg := OnboardingConfig{HTTPClient: srv.Client(), endpoint: srv.URL}
		_, err := cfg.shorten(context.Background(), "https://app.vori.com/welcome")
		require.Error(t, err)
	})
}

func TestOnboardingTools_RejectsIncompleteConfig(t *testing.T) {
	complete := func() OnboardingConfig {
		return OnboardingConfig{
			SigningKey:      []byte("invitation-signing-secret-value-32b"),
			DefaultTokenTTL: 7 * 24 * time.Hour,
			AppRootURL:      "https://app.vori.com",
			Issuer:          "https://jwt.vori.com",
			TinyURLAPIKey:   "tinyurl-key",
			ShortenerDomain: "link.vori.io",
		}
	}

	t.Run("a complete config builds", func(t *testing.T) {
		tools, err := OnboardingTools(complete())
		require.NoError(t, err)
		assert.Len(t, tools, 1)
	})

	cases := map[string]func(*OnboardingConfig){
		"signing key":       func(c *OnboardingConfig) { c.SigningKey = nil },
		"app root URL":      func(c *OnboardingConfig) { c.AppRootURL = "" },
		"issuer":            func(c *OnboardingConfig) { c.Issuer = "" },
		"shortener API key": func(c *OnboardingConfig) { c.TinyURLAPIKey = "" },
		"shortener domain":  func(c *OnboardingConfig) { c.ShortenerDomain = "" },
		"default TTL":       func(c *OnboardingConfig) { c.DefaultTokenTTL = 0 },
	}
	for field, blank := range cases {
		t.Run("rejects a blank "+field, func(t *testing.T) {
			cfg := complete()
			blank(&cfg)
			tools, err := OnboardingTools(cfg)
			require.Error(t, err)
			assert.Nil(t, tools)
			assert.Contains(t, err.Error(), field, "the error must name the field to fix")
		})
	}

	t.Run("names every blank field at once", func(t *testing.T) {
		_, err := OnboardingTools(OnboardingConfig{})
		require.Error(t, err)
		for _, field := range []string{"signing key", "app root URL", "issuer", "shortener API key", "shortener domain", "default TTL"} {
			assert.Contains(t, err.Error(), field)
		}
	})
}
