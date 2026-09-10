package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stainless-api/mcp-front/internal/config"
)

func TestHMACJWTSource_Mint(t *testing.T) {
	secret := "test-secret-at-least-32-bytes-long!!"
	src, err := NewHMACJWTSource(&config.HMACJWTAuthConfig{
		Secret:    config.Secret(secret),
		Algorithm: "HS256",
		Claims:    map[string]any{"internal": true},
		TTL:       time.Hour,
	})
	require.NoError(t, err)

	tok, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "Bearer", tok.TokenType)

	parts := strings.Split(tok.AccessToken, ".")
	require.Len(t, parts, 3)

	// Verify signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	assert.Equal(t, wantSig, parts[2])

	// Verify claims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, true, claims["internal"])
	assert.NotNil(t, claims["exp"])
}

func TestSignHS256(t *testing.T) {
	secret := []byte("test-secret-at-least-32-bytes-long!!")

	token, err := SignHS256(secret, map[string]any{"sub": "ae@vori.com", "exp": int64(1893456000)})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"alg":"HS256","typ":"JWT"}`, string(header))

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), parts[2])

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, "ae@vori.com", claims["sub"])
	assert.Equal(t, float64(1893456000), claims["exp"])
}

// Token delegates to SignHS256; the two must stay byte-identical.
func TestSignHS256_MatchesTokenEncoding(t *testing.T) {
	secret := "test-secret-at-least-32-bytes-long!!"
	src, err := NewHMACJWTSource(&config.HMACJWTAuthConfig{
		Secret:    config.Secret(secret),
		Algorithm: "HS256",
		Claims:    map[string]any{"internal": true},
		TTL:       time.Hour,
	})
	require.NoError(t, err)

	tok, err := src.Token()
	require.NoError(t, err)

	parts := strings.Split(tok.AccessToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	direct, err := SignHS256([]byte(secret), claims)
	require.NoError(t, err)
	assert.Equal(t, tok.AccessToken, direct)
}

func TestHMACJWTSource_CachesAndRefreshes(t *testing.T) {
	src, err := NewHMACJWTSource(&config.HMACJWTAuthConfig{
		Secret:    config.Secret("s"),
		Algorithm: "HS256",
		TTL:       time.Hour,
	})
	require.NoError(t, err)

	first, err := src.Token()
	require.NoError(t, err)
	second, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, first.AccessToken, second.AccessToken, "token should be cached while fresh")

	// Force near-expiry to trigger a refresh. Claim exp is Unix seconds, so
	// a re-mint within the same wall-clock second would produce an identical
	// token; bump TTL to guarantee a different exp value.
	src.exp = time.Now().Add(30 * time.Second)
	src.ttl = 2 * time.Hour
	third, err := src.Token()
	require.NoError(t, err)
	assert.NotEqual(t, first.AccessToken, third.AccessToken, "token should refresh when under 1min of expiry")
}

func TestNewHMACJWTSource_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.HMACJWTAuthConfig
		wantErr string
	}{
		{"nil config", nil, "nil"},
		{"bad alg", &config.HMACJWTAuthConfig{Algorithm: "RS256", Secret: "s", TTL: time.Hour}, "algorithm"},
		{"empty secret", &config.HMACJWTAuthConfig{Algorithm: "HS256", TTL: time.Hour}, "secret"},
		{"zero ttl", &config.HMACJWTAuthConfig{Algorithm: "HS256", Secret: "s"}, "ttl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHMACJWTSource(tc.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
