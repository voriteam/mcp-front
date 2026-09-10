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

// The backend's InvitationTokensService.verify rejects anything else, so this
// asserts the exact claim set rather than a subset.
func TestCreateLink_TokenShape(t *testing.T) {
	var captured string
	shortener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		captured = body["url"]
		_, _ = io.WriteString(w, `{"data":{"tiny_url":"https://link.vori.io/abc123"}}`)
	}))
	defer shortener.Close()

	cfg := OnboardingConfig{
		SigningKey:      []byte("invitation-signing-secret-value-32b"),
		DefaultTokenTTL: 7 * 24 * time.Hour,
		AppRootURL:      "https://app.vori.com",
		Issuer:          "https://jwt.vori.com",
		HTTPClient:      shortener.Client(),
	}
	cfg.endpoint = shortener.URL
	cfg.TinyURLAPIKey = "tinyurl-key"
	cfg.ShortenerDomain = "link.vori.io"
	tools, err := OnboardingTools(cfg)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	args := json.RawMessage(`{"hubspotDealId":"12345","recipientEmail":"buyer@grocer.example"}`)
	res, err := tools[0].Handler(context.Background(), "ae@vori.com", args)
	require.NoError(t, err)
	require.NotNil(t, res)

	parsed, err := url.Parse(captured)
	require.NoError(t, err)
	assert.Equal(t, "https", parsed.Scheme)
	assert.Equal(t, "app.vori.com", parsed.Host)
	assert.Equal(t, "/welcome", parsed.Path)

	token := parsed.Query().Get("token")
	require.NotEmpty(t, token)

	claims := decodeClaims(t, token)
	assert.Equal(t, "signing", claims["invitation_type"])
	assert.Equal(t, "12345", claims["hubspot_deal_id"])
	assert.Equal(t, "buyer@grocer.example", claims["email"])
	assert.Equal(t, "https://jwt.vori.com", claims["iss"])

	assert.ElementsMatch(t,
		[]string{"invitation_type", "hubspot_deal_id", "email", "iss", "iat", "exp"},
		keysOf(claims),
		"claim set must match the backend verifier exactly")

	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(7*24*time.Hour/time.Second), exp-iat)
}

func keysOf(m map[string]any) []string {
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
		_, err := tool.Handler(context.Background(), "ae@vori.com",
			json.RawMessage(`{"hubspotDealId":"1","recipientEmail":"b@g.example"}`))
		require.NoError(t, err)

		claims := claimsFromLink(t, *long)
		assert.Equal(t, float64(7*24*60*60), claims["exp"].(float64)-claims["iat"].(float64))
	})

	t.Run("honours a caller-supplied expiry", func(t *testing.T) {
		tool, long := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
		_, err := tool.Handler(context.Background(), "ae@vori.com",
			json.RawMessage(`{"hubspotDealId":"1","recipientEmail":"b@g.example","expiresInDays":14}`))
		require.NoError(t, err)

		claims := claimsFromLink(t, *long)
		assert.Equal(t, float64(14*24*60*60), claims["exp"].(float64)-claims["iat"].(float64))
	})

	t.Run("rejects out-of-range expiries", func(t *testing.T) {
		tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
		for _, days := range []string{"0", "-1", "91"} {
			res, err := tool.Handler(context.Background(), "ae@vori.com",
				json.RawMessage(`{"hubspotDealId":"1","recipientEmail":"b@g.example","expiresInDays":`+days+`}`))
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

func TestCreateLink_RejectsBadArguments(t *testing.T) {
	tool, _ := newLinkTool(t, OnboardingConfig{DefaultTokenTTL: 7 * 24 * time.Hour})
	cases := []struct {
		name string
		args string
	}{
		{"no deal", `{"recipientEmail":"buyer@grocer.example"}`},
		{"no email", `{"hubspotDealId":"12345"}`},
		{"malformed", `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tool.Handler(context.Background(), "ae@vori.com", json.RawMessage(tc.args))
			require.NoError(t, err, "bad input is a tool error, not a Go error")
			require.NotNil(t, res)
			assert.True(t, res.IsError)
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
