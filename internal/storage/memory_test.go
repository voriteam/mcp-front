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

func TestMemoryStorageIdentityToken(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	_, err := s.GetIdentityToken(ctx, "a@x.com")
	assert.ErrorIs(t, err, ErrIdentityTokenNotFound)

	assert.NoError(t, s.SetIdentityToken(ctx, "a@x.com", "refresh-1"))
	tok, err := s.GetIdentityToken(ctx, "a@x.com")
	assert.NoError(t, err)
	assert.Equal(t, "refresh-1", tok)

	assert.NoError(t, s.SetIdentityToken(ctx, "a@x.com", "refresh-2"))
	tok, err = s.GetIdentityToken(ctx, "a@x.com")
	assert.NoError(t, err)
	assert.Equal(t, "refresh-2", tok)

	assert.NoError(t, s.DeleteIdentityToken(ctx, "a@x.com"))
	_, err = s.GetIdentityToken(ctx, "a@x.com")
	assert.ErrorIs(t, err, ErrIdentityTokenNotFound)
}

func TestMemoryStorageRevokeUserSessions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()

	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s1", UserEmail: "a@x.com"}))
	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s2", UserEmail: "a@x.com"}))
	assert.NoError(t, s.TrackSession(ctx, ActiveSession{SessionID: "s3", UserEmail: "b@x.com"}))

	assert.NoError(t, s.RevokeUserSessions(ctx, "a@x.com"))

	_, aStillThere := s.sessions["s1"]
	assert.False(t, aStillThere)
	_, bStillThere := s.sessions["s3"]
	assert.True(t, bStillThere)
}
