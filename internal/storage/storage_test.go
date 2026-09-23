package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestMemoryStorageConfidentialClient(t *testing.T) {
	store := NewMemoryStorage()

	clientID := "test-client-123"
	secret, err := crypto.GenerateSecureToken()
	assert.NoError(t, err)
	hashedSecret, err := crypto.HashClientSecret(secret)
	assert.NoError(t, err)

	redirectURIs := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}
	issuer := "https://issuer.example.com"

	client, err := store.CreateConfidentialClient(context.Background(), clientID, hashedSecret, redirectURIs, scopes, issuer)
	assert.NoError(t, err)

	assert.Equal(t, clientID, client.ID)
	assert.Equal(t, hashedSecret, client.Secret)
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.ElementsMatch(t, scopes, client.Scopes)
	assert.ElementsMatch(t, []string{issuer}, client.Audience)
	assert.False(t, client.Public)

	ctx := context.Background()
	storedClient, err := store.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, storedClient)
	assert.Equal(t, clientID, storedClient.GetID())
	assert.False(t, storedClient.IsPublic())

	err = bcrypt.CompareHashAndPassword(storedClient.GetSecret(), []byte(secret))
	assert.NoError(t, err, "Original secret should verify against stored hash")
}

func TestMemoryStoragePublicVsConfidential(t *testing.T) {
	store := NewMemoryStorage()

	publicClient, err := store.CreateClient(context.Background(), "public-123", []string{"https://public.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.True(t, publicClient.Public)
	assert.Nil(t, publicClient.Secret)

	hashedSecret := []byte("hashed-secret")
	confidentialClient, err := store.CreateConfidentialClient(context.Background(), "confidential-123", hashedSecret, []string{"https://confidential.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.False(t, confidentialClient.Public)
	assert.NotNil(t, confidentialClient.Secret)
	assert.Equal(t, hashedSecret, confidentialClient.Secret)
}

func TestMemoryStorageGrants(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	grant := &oauth.Grant{
		Code:        "test-code",
		ClientID:    "client-123",
		RedirectURI: "https://example.com/callback",
		Identity: idp.Identity{
			Email:  "user@example.com",
			Domain: "example.com",
		},
		Scopes:        []string{"read", "write"},
		Audience:      []string{"https://issuer.com"},
		PKCEChallenge: "challenge-value",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	t.Run("store and consume", func(t *testing.T) {
		err := store.StoreGrant(ctx, grant.Code, grant)
		require.NoError(t, err)

		consumed, err := store.ConsumeGrant(ctx, grant.Code)
		require.NoError(t, err)
		assert.Equal(t, grant.ClientID, consumed.ClientID)
		assert.Equal(t, grant.Identity.Email, consumed.Identity.Email)
		assert.Equal(t, grant.Scopes, consumed.Scopes)
		assert.Equal(t, grant.PKCEChallenge, consumed.PKCEChallenge)
	})

	t.Run("consume is one-time", func(t *testing.T) {
		err := store.StoreGrant(ctx, "one-time-code", grant)
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})

	t.Run("consume nonexistent grant", func(t *testing.T) {
		_, err := store.ConsumeGrant(ctx, "nonexistent")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})
}

func TestMemoryStorageClientIsolation(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	uris := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}

	_, err := store.CreateClient(ctx, "client-1", uris, scopes, "https://issuer.com")
	require.NoError(t, err)

	uris[0] = "https://attacker.com/callback"
	scopes[0] = "admin"

	stored, err := store.GetClient(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/callback", stored.RedirectURIs[0], "stored client should not be affected by caller mutation")
	assert.Equal(t, "read", stored.Scopes[0], "stored client should not be affected by caller mutation")
}

func TestMemoryStorageGetClientIsolation(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	_, err := store.CreateClient(ctx, "client-2", []string{"https://example.com/callback"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)

	c1, _ := store.GetClient(ctx, "client-2")
	c2, _ := store.GetClient(ctx, "client-2")

	c1.RedirectURIs[0] = "https://attacker.com"

	assert.Equal(t, "https://example.com/callback", c2.RedirectURIs[0], "mutating one copy should not affect another")
}

func TestMemoryStorageSessions(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	t.Run("track new session", func(t *testing.T) {
		created := time.Now().Add(-1 * time.Minute)
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
			Created:    created,
		})
		require.NoError(t, err)

		store.sessionsMutex.RLock()
		require.Len(t, store.sessions, 1)
		sess := store.sessions["sess-1"]
		store.sessionsMutex.RUnlock()
		require.NotNil(t, sess)
		assert.Equal(t, "sess-1", sess.SessionID)
		assert.Equal(t, "user@example.com", sess.UserEmail)
		assert.Equal(t, "postgres", sess.ServerName)
		assert.WithinDuration(t, created, sess.Created, time.Second)
		assert.WithinDuration(t, time.Now(), sess.LastActive, time.Second)
	})

	t.Run("track session sets Created when zero", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-zero",
			UserEmail:  "user@example.com",
			ServerName: "linear",
		})
		require.NoError(t, err)

		store.sessionsMutex.RLock()
		sess := store.sessions["sess-zero"]
		store.sessionsMutex.RUnlock()
		require.NotNil(t, sess)
		assert.WithinDuration(t, time.Now(), sess.Created, time.Second)
	})

	t.Run("track existing session updates LastActive", func(t *testing.T) {
		store.sessionsMutex.RLock()
		before := *store.sessions["sess-1"]
		store.sessionsMutex.RUnlock()

		time.Sleep(10 * time.Millisecond)
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
		})
		require.NoError(t, err)

		store.sessionsMutex.RLock()
		after := *store.sessions["sess-1"]
		store.sessionsMutex.RUnlock()
		assert.True(t, after.LastActive.After(before.LastActive))
	})

	t.Run("revoke session", func(t *testing.T) {
		err := store.RevokeSession(ctx, "sess-1")
		require.NoError(t, err)

		store.sessionsMutex.RLock()
		_, exists := store.sessions["sess-1"]
		store.sessionsMutex.RUnlock()
		assert.False(t, exists)
	})

	t.Run("revoke nonexistent session is idempotent", func(t *testing.T) {
		err := store.RevokeSession(ctx, "nonexistent")
		require.NoError(t, err)
	})
}

func TestUserTokenMetadataCarriesNoTokenValue(t *testing.T) {
	allowed := map[string]reflect.Type{
		"UserEmail":       reflect.TypeFor[string](),
		"Service":         reflect.TypeFor[string](),
		"Type":            reflect.TypeFor[TokenType](),
		"UpdatedAt":       reflect.TypeFor[time.Time](),
		"ExpiresAt":       reflect.TypeFor[time.Time](),
		"HasRefreshToken": reflect.TypeFor[bool](),
	}

	fields := map[string]reflect.Type{}
	typ := reflect.TypeFor[UserTokenMetadata]()
	for i := range typ.NumField() {
		fields[typ.Field(i).Name] = typ.Field(i).Type
	}
	assert.Equal(t, allowed, fields, "UserTokenMetadata is shown to every signed-in user; a new field must not be able to carry a token value")
}

// seedConnectionDirectory stores tokens whose values all contain "SECRET", so
// callers can assert no value leaks into what the directory returns.
func seedConnectionDirectory(t *testing.T, ctx context.Context, s Storage, expiresAt time.Time) {
	t.Helper()
	require.NoError(t, s.SetUserToken(ctx, "a@example.com", "linear", &StoredToken{
		Type: TokenTypeOAuth,
		OAuthData: &OAuthTokenData{
			AccessToken:  "access-SECRET-a",
			RefreshToken: "refresh-SECRET-a",
			ExpiresAt:    expiresAt,
		},
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, s.SetUserToken(ctx, "b@example.com", "linear", &StoredToken{
		Type: TokenTypeOAuth,
		OAuthData: &OAuthTokenData{
			AccessToken: "access-SECRET-b",
			ExpiresAt:   expiresAt,
		},
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, s.SetUserToken(ctx, "a@example.com", "notion", &StoredToken{
		Type:      TokenTypeManual,
		Value:     "manual-SECRET-a",
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, s.SetUserToken(ctx, "d@example.com", "github", &StoredToken{
		Type:      TokenTypeManual,
		Value:     "manual-SECRET-d",
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, s.SetIdentityToken(ctx, "a@example.com", "idp-SECRET-a"))
	require.NoError(t, s.SetIdentityToken(ctx, "c@example.com", "idp-SECRET-c"))
}

func assertConnectionDirectory(t *testing.T, ctx context.Context, s Storage, expiresAt time.Time) {
	t.Helper()

	metadata, err := s.ListUserTokenMetadata(ctx)
	require.NoError(t, err)
	require.Len(t, metadata, 4)

	type key struct{ email, service string }
	byKey := map[key]UserTokenMetadata{}
	for _, m := range metadata {
		byKey[key{m.UserEmail, m.Service}] = m
		assert.False(t, m.UpdatedAt.IsZero(), "updated_at for %s/%s", m.UserEmail, m.Service)
	}

	withRefresh := byKey[key{"a@example.com", "linear"}]
	assert.Equal(t, TokenTypeOAuth, withRefresh.Type)
	assert.True(t, withRefresh.HasRefreshToken)
	assert.True(t, expiresAt.Equal(withRefresh.ExpiresAt), "expires_at %v != %v", withRefresh.ExpiresAt, expiresAt)

	withoutRefresh := byKey[key{"b@example.com", "linear"}]
	assert.Equal(t, TokenTypeOAuth, withoutRefresh.Type)
	assert.False(t, withoutRefresh.HasRefreshToken)
	assert.True(t, expiresAt.Equal(withoutRefresh.ExpiresAt))

	manual := byKey[key{"a@example.com", "notion"}]
	assert.Equal(t, TokenTypeManual, manual.Type)
	assert.False(t, manual.HasRefreshToken)
	assert.True(t, manual.ExpiresAt.IsZero())

	orphan, ok := byKey[key{"d@example.com", "github"}]
	assert.True(t, ok, "token for an unconfigured service must still be listed")
	assert.Equal(t, TokenTypeManual, orphan.Type)

	assert.NotContains(t, fmt.Sprintf("%+v", metadata), "SECRET")

	users, err := s.ListIdentityTokenUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"a@example.com", "c@example.com"}, users)
}
