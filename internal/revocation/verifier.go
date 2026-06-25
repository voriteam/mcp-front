// Package revocation enforces that a user who can no longer authenticate with the
// identity provider also loses access to mcp-front.
//
// At login mcp-front stores the user's IdP refresh token. When an mcp-front token
// is refreshed, the Verifier replays that stored token against the IdP: the
// provider rejects it once the account is suspended, deleted, or its consent is
// revoked. On rejection the user's stored upstream tokens and sessions are purged
// and the refresh is denied; the dead identity token is kept so every later
// refresh stays denied until a genuine re-login replaces it. This keys off the
// user's own authentication, so it needs no directory access or admin privileges.
//
// Enforcement is eventual: an access token already issued remains valid until it
// expires within its TTL; the Verifier blocks the minting of new ones.
package revocation

import (
	"context"
	"errors"

	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/storage"
	"golang.org/x/oauth2"
)

// Store is the subset of storage the verifier needs.
type Store interface {
	GetIdentityToken(ctx context.Context, userEmail string) (string, error)
	SetIdentityToken(ctx context.Context, userEmail, refreshToken string) error
	DeleteIdentityToken(ctx context.Context, userEmail string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	RevokeUserSessions(ctx context.Context, userEmail string) error
}

// IdentityRefresher replays a stored refresh token against the identity provider.
// It is satisfied by the Google IdP provider.
type IdentityRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

// Verifier implements oauth.RevocationChecker. IsUserRevoked returns true (and
// purges the account) when the user's IdP account is no longer valid.
type Verifier struct {
	store     Store
	refresher IdentityRefresher
}

func NewVerifier(store Store, refresher IdentityRefresher) *Verifier {
	return &Verifier{store: store, refresher: refresher}
}

// IsUserRevoked replays the user's stored IdP refresh token. The policy is "deny
// unless positively verified active": a definitive "invalid_grant" rejection
// revokes and purges the user, and a missing stored token denies the refresh
// (forcing re-authentication, which Google gates). Only transient errors reaching
// the provider or storage fail open, so a brief outage cannot lock everyone out.
func (v *Verifier) IsUserRevoked(ctx context.Context, userEmail string) (bool, error) {
	refreshToken, err := v.store.GetIdentityToken(ctx, userEmail)
	if errors.Is(err, storage.ErrIdentityTokenNotFound) {
		log.LogInfoWithFields("revocation", "No stored identity token; denying refresh to force re-authentication", map[string]any{
			"email": userEmail,
		})
		return true, nil
	}
	if err != nil {
		log.LogWarnWithFields("revocation", "Could not load identity token; allowing refresh", map[string]any{
			"email": userEmail,
			"error": err.Error(),
		})
		return false, nil
	}

	token, err := v.refresher.RefreshToken(ctx, refreshToken)
	if err != nil {
		if isInvalidGrant(err) {
			log.LogInfoWithFields("revocation", "Identity provider rejected refresh token; revoking user", map[string]any{
				"email": userEmail,
			})
			v.purge(ctx, userEmail)
			return true, nil
		}
		log.LogWarnWithFields("revocation", "Transient identity refresh error; allowing refresh", map[string]any{
			"email": userEmail,
			"error": err.Error(),
		})
		return false, nil
	}

	// Persist a rotated refresh token so future checks keep working.
	if token != nil && token.RefreshToken != "" && token.RefreshToken != refreshToken {
		if err := v.store.SetIdentityToken(ctx, userEmail, token.RefreshToken); err != nil {
			log.LogWarnWithFields("revocation", "Failed to persist rotated identity token", map[string]any{
				"email": userEmail,
				"error": err.Error(),
			})
		}
	}
	return false, nil
}

// purge removes a revoked user's stored upstream service tokens and sessions.
//
// It deliberately leaves the identity token in place: that token is what failed
// the probe, so keeping it makes the lockout durable — every subsequent refresh
// re-detects the dead token and is denied. Deleting it would drop the user into
// the "no stored token" fail-open path and let them refresh again. A genuine
// re-login (only possible for a re-enabled account) overwrites the dead token
// with a fresh one and restores access.
func (v *Verifier) purge(ctx context.Context, userEmail string) {
	services, err := v.store.ListUserServices(ctx, userEmail)
	if err != nil {
		log.LogErrorWithFields("revocation", "Failed to list services for revoked user", map[string]any{
			"email": userEmail,
			"error": err.Error(),
		})
	}
	for _, service := range services {
		if err := v.store.DeleteUserToken(ctx, userEmail, service); err != nil {
			log.LogErrorWithFields("revocation", "Failed to delete stored token", map[string]any{
				"email":   userEmail,
				"service": service,
				"error":   err.Error(),
			})
		}
	}
	if err := v.store.RevokeUserSessions(ctx, userEmail); err != nil {
		log.LogErrorWithFields("revocation", "Failed to revoke sessions", map[string]any{
			"email": userEmail,
			"error": err.Error(),
		})
	}
}

// isInvalidGrant reports whether an IdP token refresh failed because the grant is
// no longer valid (account suspended/deleted or consent revoked), as opposed to a
// transient/network error.
func isInvalidGrant(err error) bool {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return re.ErrorCode == "invalid_grant"
	}
	return false
}
