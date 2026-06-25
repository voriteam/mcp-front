package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/stainless-api/mcp-front/internal/config"
)

// HMACJWTSource is an oauth2.TokenSource that mints HMAC-signed JWTs from a
// shared secret. It refreshes the token before expiry.
type HMACJWTSource struct {
	secret []byte
	claims map[string]any
	ttl    time.Duration

	mu    sync.Mutex
	token string
	exp   time.Time
}

// NewHMACJWTSource builds a token source from an HMACJWTAuthConfig. It returns
// an error if the config is malformed or the algorithm is unsupported.
func NewHMACJWTSource(cfg *config.HMACJWTAuthConfig) (*HMACJWTSource, error) {
	if cfg == nil {
		return nil, fmt.Errorf("hmacJWT config is nil")
	}
	if cfg.Algorithm != "HS256" {
		return nil, fmt.Errorf("algorithm %q not supported (only HS256)", cfg.Algorithm)
	}
	if len(cfg.Secret) == 0 {
		return nil, fmt.Errorf("hmacJWT.secret is empty")
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("hmacJWT.ttl must be positive, got %s", cfg.TTL)
	}
	claims := make(map[string]any, len(cfg.Claims))
	for k, v := range cfg.Claims {
		claims[k] = v
	}
	return &HMACJWTSource{
		secret: []byte(cfg.Secret),
		claims: claims,
		ttl:    cfg.TTL,
	}, nil
}

// Token returns a valid JWT, minting a new one if the cached one is nil or
// within 60s of expiry.
func (s *HMACJWTSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Until(s.exp) > time.Minute {
		return &oauth2.Token{AccessToken: s.token, TokenType: "Bearer", Expiry: s.exp}, nil
	}

	exp := time.Now().Add(s.ttl)
	payload := make(map[string]any, len(s.claims)+1)
	for k, v := range s.claims {
		payload[k] = v
	}
	payload["exp"] = exp.Unix()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString(payloadJSON)
	unsigned := header + "." + body

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	s.token = unsigned + "." + sig
	s.exp = exp
	return &oauth2.Token{AccessToken: s.token, TokenType: "Bearer", Expiry: exp}, nil
}
