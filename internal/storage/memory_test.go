package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryStorageDefault(t *testing.T) {
	storage := NewMemoryStorage()
	assert.NotNil(t, storage, "Expected storage to be created")
}

func TestMemoryStorageRevocation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	revoked, err := s.IsUserRevoked(ctx, "a@x.com")
	assert.NoError(t, err)
	assert.False(t, revoked)

	assert.NoError(t, s.AddRevokedUser(ctx, "a@x.com", "suspended"))
	revoked, err = s.IsUserRevoked(ctx, "a@x.com")
	assert.NoError(t, err)
	assert.True(t, revoked)

	list, err := s.ListRevokedUsers(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"a@x.com"}, list)

	assert.NoError(t, s.RemoveRevokedUser(ctx, "a@x.com"))
	revoked, err = s.IsUserRevoked(ctx, "a@x.com")
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestMemoryStorageReconcilerHelpers(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	tok := &StoredToken{Type: TokenTypeManual, Value: "v"}
	assert.NoError(t, s.SetUserToken(ctx, "a@x.com", "linear", tok))
	assert.NoError(t, s.SetUserToken(ctx, "a@x.com", "postgres", tok))
	assert.NoError(t, s.SetUserToken(ctx, "b@x.com", "linear", tok))

	withTokens, err := s.ListUsersWithTokens(ctx)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"a@x.com", "b@x.com"}, withTokens)

	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s1", UserEmail: "a@x.com"}))
	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s2", UserEmail: "a@x.com"}))
	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s3", UserEmail: "b@x.com"}))

	withSessions, err := s.ListUsersWithSessions(ctx)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"a@x.com", "b@x.com"}, withSessions)

	assert.NoError(t, s.RevokeUserSessions(ctx, "a@x.com"))
	withSessions, err = s.ListUsersWithSessions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"b@x.com"}, withSessions)
}
