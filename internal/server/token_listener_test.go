package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stainless-api/mcp-front/internal/auth"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenChange struct {
	userEmail   string
	serviceName string
}

type recordingTokenListener struct {
	mu      sync.Mutex
	changes []tokenChange
}

func (l *recordingTokenListener) UserTokenChanged(userEmail, serviceName string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.changes = append(l.changes, tokenChange{userEmail: userEmail, serviceName: serviceName})
}

func (l *recordingTokenListener) recorded() []tokenChange {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]tokenChange(nil), l.changes...)
}

func postForm(t *testing.T, handler http.HandlerFunc, path, userEmail string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), oauth.GetUserContextKey(), userEmail))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestTokenHandlersNotifyListenerOfTokenChanges(t *testing.T) {
	const userEmail = "user@example.com"
	store := storage.NewMemoryStorage()
	listener := &recordingTokenListener{}
	mcpServers := map[string]*config.MCPClientConfig{
		"notion": {
			RequiresUserToken:  true,
			UserAuthentication: &config.UserAuthentication{Type: config.UserAuthTypeManual},
		},
	}
	handlers := NewTokenHandlers(store, listener, mcpServers, nil, []byte(strings.Repeat("k", 32)))

	csrf, err := handlers.csrf.Generate()
	require.NoError(t, err)

	rec := postForm(t, handlers.SetTokenHandler, "/my/tokens/set", userEmail, url.Values{"csrf_token": {csrf}, "service": {"notion"}, "token": {"secret"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []tokenChange{{userEmail, "notion"}}, listener.recorded())

	rec = postForm(t, handlers.SetTokenHandler, "/my/tokens/set", userEmail, url.Values{"csrf_token": {csrf}, "service": {"notion"}, "token": {""}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Len(t, listener.recorded(), 1, "a rejected token must not notify")

	rec = postForm(t, handlers.DeleteTokenHandler, "/my/tokens/delete", userEmail, url.Values{"csrf_token": {csrf}, "service": {"notion"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []tokenChange{{userEmail, "notion"}, {userEmail, "notion"}}, listener.recorded())
}

func TestDisconnectHandlerNotifiesListener(t *testing.T) {
	const userEmail = "user@example.com"
	store := storage.NewMemoryStorage()
	listener := &recordingTokenListener{}
	oauthClient := auth.NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("k", 32)))
	handlers := NewServiceAuthHandlers(oauthClient, map[string]*config.MCPClientConfig{}, store, listener)

	require.NoError(t, store.SetUserToken(context.Background(), userEmail, "linear", &storage.StoredToken{
		Type:      storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{AccessToken: "token"},
	}))

	rec := postForm(t, handlers.DisconnectHandler, "/oauth/disconnect", userEmail, url.Values{"service": {"linear"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []tokenChange{{userEmail, "linear"}}, listener.recorded())
}
