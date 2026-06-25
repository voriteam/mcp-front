package revocation

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeStore is a minimal in-memory Store for verifier tests.
type fakeStore struct {
	identity map[string]string
	tokens   map[string][]string // email -> services
	sessions map[string]bool     // email -> has sessions
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		identity: map[string]string{},
		tokens:   map[string][]string{},
		sessions: map[string]bool{},
	}
}

func (f *fakeStore) GetIdentityToken(_ context.Context, email string) (string, error) {
	t, ok := f.identity[email]
	if !ok {
		return "", storage.ErrIdentityTokenNotFound
	}
	return t, nil
}
func (f *fakeStore) SetIdentityToken(_ context.Context, email, rt string) error {
	f.identity[email] = rt
	return nil
}
func (f *fakeStore) DeleteIdentityToken(_ context.Context, email string) error {
	delete(f.identity, email)
	return nil
}
func (f *fakeStore) ListUserServices(_ context.Context, email string) ([]string, error) {
	return f.tokens[email], nil
}
func (f *fakeStore) DeleteUserToken(_ context.Context, email, service string) error {
	rest := f.tokens[email][:0]
	for _, s := range f.tokens[email] {
		if s != service {
			rest = append(rest, s)
		}
	}
	f.tokens[email] = rest
	return nil
}
func (f *fakeStore) RevokeUserSessions(_ context.Context, email string) error {
	delete(f.sessions, email)
	return nil
}

type fakeRefresher struct {
	err   error
	token *oauth2.Token
}

func (f *fakeRefresher) RefreshToken(_ context.Context, _ string) (*oauth2.Token, error) {
	return f.token, f.err
}

func invalidGrantErr() error {
	return &oauth2.RetrieveError{
		Response:  &http.Response{StatusCode: 400},
		ErrorCode: "invalid_grant",
	}
}

func TestVerifier_NoStoredToken_DeniesWithoutPurge(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.tokens["u@x.com"] = []string{"linear"}
	v := NewVerifier(store, &fakeRefresher{token: &oauth2.Token{}})

	// No stored identity token: cannot positively verify the account, so deny the
	// refresh (forcing re-auth) — but don't purge, since we have no evidence the
	// account is gone.
	revoked, err := v.IsUserRevoked(ctx, "u@x.com")
	require.NoError(t, err)
	assert.True(t, revoked)
	assert.Equal(t, []string{"linear"}, store.tokens["u@x.com"], "must not purge on missing token")
}

func TestVerifier_InvalidGrant_RevokesAndPurges(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.identity["u@x.com"] = "rt"
	store.tokens["u@x.com"] = []string{"linear", "sentry"}
	store.sessions["u@x.com"] = true
	v := NewVerifier(store, &fakeRefresher{err: invalidGrantErr()})

	revoked, err := v.IsUserRevoked(ctx, "u@x.com")
	require.NoError(t, err)
	assert.True(t, revoked)
	assert.Empty(t, store.tokens["u@x.com"], "upstream tokens purged")
	assert.False(t, store.sessions["u@x.com"], "sessions revoked")
	_, ok := store.identity["u@x.com"]
	assert.True(t, ok, "dead identity token kept so the lockout stays durable")
}

func TestVerifier_TransientError_AllowsAndKeepsState(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.identity["u@x.com"] = "rt"
	store.tokens["u@x.com"] = []string{"linear"}
	v := NewVerifier(store, &fakeRefresher{err: errors.New("network blip")})

	revoked, err := v.IsUserRevoked(ctx, "u@x.com")
	require.NoError(t, err)
	assert.False(t, revoked, "transient errors must not revoke")
	assert.Equal(t, []string{"linear"}, store.tokens["u@x.com"])
	assert.Equal(t, "rt", store.identity["u@x.com"])
}

func TestVerifier_Success_PersistsRotatedToken(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.identity["u@x.com"] = "rt-old"
	v := NewVerifier(store, &fakeRefresher{token: &oauth2.Token{RefreshToken: "rt-new"}})

	revoked, err := v.IsUserRevoked(ctx, "u@x.com")
	require.NoError(t, err)
	assert.False(t, revoked)
	assert.Equal(t, "rt-new", store.identity["u@x.com"], "rotated refresh token persisted")
}
