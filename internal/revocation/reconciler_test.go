package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecide(t *testing.T) {
	candidates := []string{"a@x.com", "b@x.com", "c@x.com", "d@x.com", "e@x.com"}
	statuses := map[string]Status{
		"a@x.com": StatusActive,    // active, not revoked -> nothing
		"b@x.com": StatusActive,    // active, revoked -> restore
		"c@x.com": StatusSuspended, // suspended, not revoked -> revoke
		"d@x.com": StatusDeleted,   // deleted, revoked -> nothing (already revoked)
		// e@x.com absent (lookup failed) -> nothing
	}
	revoked := map[string]bool{"b@x.com": true, "d@x.com": true}

	toRevoke, toRestore := decide(candidates, statuses, revoked)

	assert.Equal(t, []string{"c@x.com"}, toRevoke)
	assert.Equal(t, []string{"b@x.com"}, toRestore)
}

type fakeDirectory struct {
	statuses map[string]Status
	errs     map[string]error
}

func (f *fakeDirectory) Status(_ context.Context, email string) (Status, error) {
	if err := f.errs[email]; err != nil {
		return StatusActive, err
	}
	if st, ok := f.statuses[email]; ok {
		return st, nil
	}
	return StatusActive, nil
}

func manualToken() *storage.StoredToken {
	return &storage.StoredToken{Type: storage.TokenTypeManual, Value: "secret"}
}

func TestReconcile_PurgesDisabledUser(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStorage()

	require.NoError(t, store.SetUserToken(ctx, "bad@x.com", "linear", manualToken()))
	require.NoError(t, store.SetUserToken(ctx, "bad@x.com", "postgres", manualToken()))
	require.NoError(t, store.TrackSession(ctx, storage.ActiveSession{SessionID: "s1", UserEmail: "bad@x.com", ServerName: "linear"}))
	require.NoError(t, store.SetUserToken(ctx, "good@x.com", "linear", manualToken()))

	dir := &fakeDirectory{statuses: map[string]Status{
		"bad@x.com":  StatusSuspended,
		"good@x.com": StatusActive,
	}}
	r := New(store, dir, time.Hour, []string{"x.com"})

	require.NoError(t, r.reconcile(ctx))

	revoked, err := store.IsUserRevoked(ctx, "bad@x.com")
	require.NoError(t, err)
	assert.True(t, revoked)

	services, err := store.ListUserServices(ctx, "bad@x.com")
	require.NoError(t, err)
	assert.Empty(t, services)

	sessions, err := store.ListUsersWithSessions(ctx)
	require.NoError(t, err)
	assert.NotContains(t, sessions, "bad@x.com")

	goodRevoked, err := store.IsUserRevoked(ctx, "good@x.com")
	require.NoError(t, err)
	assert.False(t, goodRevoked)
	goodServices, err := store.ListUserServices(ctx, "good@x.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"linear"}, goodServices)
}

func TestReconcile_RestoresReenabledUser(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStorage()
	require.NoError(t, store.AddRevokedUser(ctx, "back@x.com", "suspended"))

	dir := &fakeDirectory{statuses: map[string]Status{"back@x.com": StatusActive}}
	r := New(store, dir, time.Hour, nil)

	require.NoError(t, r.reconcile(ctx))

	revoked, err := store.IsUserRevoked(ctx, "back@x.com")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestReconcile_SkipsOnLookupError(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStorage()
	require.NoError(t, store.SetUserToken(ctx, "flap@x.com", "linear", manualToken()))

	dir := &fakeDirectory{errs: map[string]error{"flap@x.com": errors.New("transient")}}
	r := New(store, dir, time.Hour, nil)

	require.NoError(t, r.reconcile(ctx))

	revoked, err := store.IsUserRevoked(ctx, "flap@x.com")
	require.NoError(t, err)
	assert.False(t, revoked, "transient lookup error must not revoke")
	services, err := store.ListUserServices(ctx, "flap@x.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"linear"}, services)
}

func TestReconcile_SkipsDisallowedDomain(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStorage()
	require.NoError(t, store.SetUserToken(ctx, "user@other.com", "linear", manualToken()))

	// Directory would report suspended, but the domain is outside the allowlist
	// so the user is never looked up or revoked.
	dir := &fakeDirectory{statuses: map[string]Status{"user@other.com": StatusSuspended}}
	r := New(store, dir, time.Hour, []string{"x.com"})

	require.NoError(t, r.reconcile(ctx))

	revoked, err := store.IsUserRevoked(ctx, "user@other.com")
	require.NoError(t, err)
	assert.False(t, revoked)
}
