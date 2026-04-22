package oauth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/emailutil"
	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
)

const userContextKey contextKey = "user_email"
const authTokenContextKey contextKey = "auth_token"

func GetAuthTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(authTokenContextKey).(string)
	return token, ok
}

func GetUserFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(userContextKey).(string)
	return email, ok
}

func GetUserContextKey() contextKey {
	return userContextKey
}

func NewSessionEncryptor(encryptionKey []byte) (crypto.Encryptor, error) {
	sessionEncryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}
	log.Logf("Session encryptor initialized for browser SSO")
	return sessionEncryptor, nil
}

func GenerateJWTSecret(providedSecret string) ([]byte, error) {
	if providedSecret != "" {
		secret := []byte(providedSecret)
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(secret))
		}
		return secret, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	log.LogWarn("Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	return secret, nil
}

// NewValidateTokenMiddleware tries to authenticate the request as an OAuth
// Bearer token, falling back to GCP service account access tokens when a
// validator is configured. On success it sets the user-email context and
// continues. On any failure (missing header, wrong scheme, invalid signature,
// expired, wrong audience) it passes through unchanged — the downstream
// RequireAuth gate produces the 401 with the RFC 9728 Bearer challenge.
func NewValidateTokenMiddleware(authServer *AuthorizationServer, issuer string, acceptIssuerAudience bool, gcpValidator *GCPAccessTokenValidator, allowedDomains []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// If service auth already authenticated this request, skip JWT
			// parsing — pure optimization, the gate would accept either way.
			if _, ok := servicecontext.GetAuthInfo(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				next.ServeHTTP(w, r)
				return
			}
			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				next.ServeHTTP(w, r)
				return
			}

			token := parts[1]
			claims, err := authServer.ValidateAccessToken(token)
			if err != nil {
				// Not one of our JWTs — try it as a GCP service account
				// access token before passing through to the gate.
				if gcpValidator == nil {
					log.LogTraceWithFields("oauth", "Token validation failed", map[string]any{"error": err.Error()})
					next.ServeHTTP(w, r)
					return
				}
				gcpEmail, gcpErr := gcpValidator.Validate(ctx, token)
				if gcpErr != nil {
					log.LogTraceWithFields("oauth", "Token validation failed", map[string]any{"error": gcpErr.Error()})
					next.ServeHTTP(w, r)
					return
				}
				userEmail := gcpEmail
				ctx = context.WithValue(ctx, authTokenContextKey, token)

				if onBehalf := r.Header.Get("X-On-Behalf-Of"); onBehalf != "" {
					domain := emailutil.ExtractDomain(onBehalf)
					if domain == "" || (len(allowedDomains) > 0 && !slices.Contains(allowedDomains, domain)) {
						jsonwriter.WriteForbidden(w, "Impersonation target not in allowed domains")
						return
					}
					log.LogInfoWithFields("oauth", "GCP service account impersonating user", map[string]any{
						"service_account": gcpEmail,
						"on_behalf_of":    onBehalf,
					})
					userEmail = onBehalf
				}

				ctx = context.WithValue(ctx, userContextKey, userEmail)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if err := ValidateAudienceForService(r.URL.Path, claims.Audience, issuer, acceptIssuerAudience); err != nil {
				log.LogErrorWithFields("oauth", "Audience validation failed", map[string]any{
					"path":     r.URL.Path,
					"audience": claims.Audience,
					"error":    err.Error(),
				})
				next.ServeHTTP(w, r)
				return
			}

			// Defense in depth: reject any token whose identity claims the
			// reserved service-auth domain (validateAccess catches this at
			// callback time; this catches refreshed/pre-existing tokens).
			if at := strings.LastIndexByte(claims.Identity.Email, '@'); at >= 0 && servicecontext.IsReservedDomain(claims.Identity.Email[at+1:]) {
				log.LogErrorWithFields("oauth", "rejected token with reserved service-auth domain in identity", map[string]any{
					"email": claims.Identity.Email,
				})
				next.ServeHTTP(w, r)
				return
			}

			ctx = context.WithValue(ctx, userContextKey, claims.Identity.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ExtractServiceNameFromPath(requestPath string, issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}

	basePath := u.Path
	if basePath == "" {
		basePath = "/"
	}

	path := requestPath
	if basePath != "/" {
		if !strings.HasPrefix(path, basePath) {
			return ""
		}
		remainder := path[len(basePath):]
		if remainder != "" && !strings.HasPrefix(remainder, "/") {
			return ""
		}
		path = remainder
	}
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		return ""
	}

	return parts[0]
}
