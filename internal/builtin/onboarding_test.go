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
		SigningKey: []byte("invitation-signing-secret-value-32b"),
		TokenTTL:   7 * 24 * time.Hour,
		AppRootURL: "https://app.vori.com",
		Issuer:     "https://jwt.vori.com",
		HTTPClient: shortener.Client(),
	}
	cfg.endpoint = shortener.URL
	tools := OnboardingTools(cfg)
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

func TestCreateLink_RejectsBadArguments(t *testing.T) {
	tools := OnboardingTools(OnboardingConfig{})
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
			res, err := tools[0].Handler(context.Background(), "ae@vori.com", json.RawMessage(tc.args))
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
		ShortenerTags:   []string{"gtm-onboarding", "ae"},
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
	assert.Equal(t, "gtm-onboarding,ae", gotBody["tags"], "tags are comma-joined")
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
