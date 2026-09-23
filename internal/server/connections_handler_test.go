package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/session"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func connectionsTestServers() map[string]*config.MCPClientConfig {
	return map[string]*config.MCPClientConfig{
		"linear": {
			URL:               "http://linear:8080",
			RequiresUserToken: true,
			UserAuthentication: &config.UserAuthentication{
				Type:        config.UserAuthTypeOAuth,
				DisplayName: "Linear",
			},
		},
		"notion": {
			URL:               "http://notion:8080",
			RequiresUserToken: true,
			UserAuthentication: &config.UserAuthentication{
				Type:        config.UserAuthTypeManual,
				DisplayName: "Notion",
			},
		},
		"postgres": {
			URL: "http://postgres:8080",
		},
	}
}

// Every seeded secret contains "SECRET" so a single substring check proves
// none of them reached the page.
func seedConnectionsStore(t *testing.T) *storage.MemoryStorage {
	t.Helper()
	ctx := context.Background()
	store := storage.NewMemoryStorage()

	require.NoError(t, store.SetUserToken(ctx, "a@example.com", "linear", &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  "access-SECRET-a",
			RefreshToken: "refresh-SECRET-a",
			ExpiresAt:    time.Now().Add(-time.Hour),
		},
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, store.SetUserToken(ctx, "b@example.com", "notion", &storage.StoredToken{
		Type:      storage.TokenTypeManual,
		Value:     "manual-SECRET-b",
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, store.SetUserToken(ctx, "d@example.com", "github", &storage.StoredToken{
		Type:      storage.TokenTypeManual,
		Value:     "manual-SECRET-d",
		UpdatedAt: time.Now(),
	}))
	require.NoError(t, store.SetIdentityToken(ctx, "a@example.com", "idp-SECRET-a"))
	require.NoError(t, store.SetIdentityToken(ctx, "c@example.com", "idp-SECRET-c"))
	return store
}

func getConnections(t *testing.T, h http.Handler, viewer, query string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), viewer)
	req := httptest.NewRequest(http.MethodGet, "/connections"+query, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConnectionsHandlerShowsEveryUser(t *testing.T) {
	h := NewConnectionsHandler(seedConnectionsStore(t), connectionsTestServers())

	rec := getConnections(t, h, "a@example.com", "")
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "a@example.com")
	assert.Contains(t, body, "b@example.com", "user with a token but no sign-in")
	assert.Contains(t, body, "c@example.com", "user who signed in but connected nothing")
	assert.Contains(t, body, "d@example.com", "user whose only token is orphaned")
	assert.Contains(t, body, "Showing 4 of 4 users")
	assert.Contains(t, body, `title="Expired, refreshable"`)
}

func TestConnectionsHandlerNeverRendersTokenValues(t *testing.T) {
	h := NewConnectionsHandler(seedConnectionsStore(t), connectionsTestServers())

	rec := getConnections(t, h, "a@example.com", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "SECRET")
}

func TestConnectionsHandlerColumnsFollowConfig(t *testing.T) {
	store := seedConnectionsStore(t)

	servers := connectionsTestServers()
	body := getConnections(t, NewConnectionsHandler(store, servers), "a@example.com", "").Body.String()
	assert.Contains(t, body, `<th class="mcp">Linear`)
	assert.Contains(t, body, `<th class="mcp">Notion`)
	assert.NotContains(t, body, `<th class="mcp">postgres`, "servers without per-user tokens get no column")
	assert.NotContains(t, body, `<th class="mcp">Zoho`)

	servers["zoho"] = &config.MCPClientConfig{
		URL:               "http://zoho:8080",
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:        config.UserAuthTypeOAuth,
			DisplayName: "Zoho",
		},
	}
	body = getConnections(t, NewConnectionsHandler(store, servers), "a@example.com", "").Body.String()
	assert.Contains(t, body, `<th class="mcp">Zoho<span class="total">0</span>`)
}

func TestConnectionsHandlerListsOrphans(t *testing.T) {
	h := NewConnectionsHandler(seedConnectionsStore(t), connectionsTestServers())

	body := getConnections(t, h, "a@example.com", "").Body.String()
	orphans := body[strings.Index(body, "Orphaned connections"):]
	assert.Contains(t, orphans, "<td>d@example.com</td>")
	assert.Contains(t, orphans, "<td>github</td>")
}

func TestConnectionsHandlerFiltersByEmail(t *testing.T) {
	h := NewConnectionsHandler(seedConnectionsStore(t), connectionsTestServers())

	body := getConnections(t, h, "a@example.com", "?q=B%40EXAMPLE").Body.String()
	assert.Contains(t, body, "<td>b@example.com</td>")
	assert.NotContains(t, body, "<td>c@example.com</td>")
	assert.NotContains(t, body, "<td>d@example.com</td>")
	assert.Contains(t, body, "Showing 1 of 4 users")
}

func TestConnectionsHandlerRejectsNonGet(t *testing.T) {
	h := NewConnectionsHandler(storage.NewMemoryStorage(), connectionsTestServers())
	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "a@example.com")
	req := httptest.NewRequest(http.MethodPost, "/connections", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestConnectionsUnauthenticatedMatchesMyTokens(t *testing.T) {
	store := seedConnectionsStore(t)
	servers := connectionsTestServers()
	encKey := []byte(strings.Repeat("b", 32))

	t.Run("no user in context", func(t *testing.T) {
		tokensRec := httptest.NewRecorder()
		NewTokenHandlers(store, servers, nil, encKey).ListTokensHandler(tokensRec, httptest.NewRequest(http.MethodGet, "/my/tokens", nil))

		connRec := httptest.NewRecorder()
		NewConnectionsHandler(store, servers).ServeHTTP(connRec, httptest.NewRequest(http.MethodGet, "/connections", nil))

		assert.Equal(t, http.StatusUnauthorized, connRec.Code)
		assert.Equal(t, tokensRec.Code, connRec.Code)
		assert.Equal(t, tokensRec.Body.String(), connRec.Body.String())
		assert.NotContains(t, connRec.Body.String(), "SECRET")
	})

	oauthConfig := config.OAuthAuthConfig{EncryptionKey: config.Secret(encKey)}
	sessionEncryptor, err := oauth.NewSessionEncryptor(encKey)
	require.NoError(t, err)
	browserStateToken := crypto.NewTokenSigner(encKey, 10*time.Minute)
	sso := NewBrowserSSOMiddleware(oauthConfig, &mockIDPProvider{}, sessionEncryptor, &browserStateToken)

	mux := http.NewServeMux()
	mux.Handle("/my/tokens", ChainMiddleware(http.HandlerFunc(NewTokenHandlers(store, servers, nil, encKey).ListTokensHandler), sso))
	mux.Handle("/connections", ChainMiddleware(NewConnectionsHandler(store, servers), sso))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(t *testing.T, path string, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	withoutState := func(t *testing.T, location string) string {
		t.Helper()
		u, err := url.Parse(location)
		require.NoError(t, err)
		q := u.Query()
		q.Del("state")
		u.RawQuery = q.Encode()
		return u.String()
	}

	t.Run("no session cookie", func(t *testing.T) {
		tokens := get(t, "/my/tokens", nil)
		conn := get(t, "/connections", nil)

		assert.Equal(t, http.StatusFound, conn.StatusCode)
		assert.Equal(t, tokens.StatusCode, conn.StatusCode)
		assert.Equal(t, withoutState(t, tokens.Header.Get("Location")), withoutState(t, conn.Header.Get("Location")))
	})

	t.Run("invalid session cookie", func(t *testing.T) {
		bad := &http.Cookie{Name: "mcp_session", Value: "not-a-valid-session"}
		tokens := get(t, "/my/tokens", bad)
		conn := get(t, "/connections", bad)

		assert.Equal(t, tokens.StatusCode, conn.StatusCode)
		assert.Equal(t, withoutState(t, tokens.Header.Get("Location")), withoutState(t, conn.Header.Get("Location")))
	})

	t.Run("valid session sees every user", func(t *testing.T) {
		cookieJSON, err := json.Marshal(session.BrowserCookie{
			Email:    "c@example.com",
			Provider: "mock",
			Expires:  time.Now().Add(time.Hour),
		})
		require.NoError(t, err)
		encrypted, err := sessionEncryptor.Encrypt(string(cookieJSON))
		require.NoError(t, err)

		resp := get(t, "/connections", &http.Cookie{Name: "mcp_session", Value: encrypted})
		require.Equal(t, http.StatusOK, resp.StatusCode)

		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		body := string(raw)
		assert.Contains(t, body, "<td>a@example.com</td>")
		assert.Contains(t, body, "<td>b@example.com</td>")
		assert.NotContains(t, body, "SECRET")
	})
}

func TestBuildConnectionsPage(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	columns := []connectionColumn{{name: "linear", displayName: "Linear"}, {name: "notion", displayName: "Notion"}}
	tokens := []storage.UserTokenMetadata{
		{UserEmail: "a@example.com", Service: "linear", Type: storage.TokenTypeOAuth, UpdatedAt: now, ExpiresAt: now.Add(-time.Minute), HasRefreshToken: true},
		{UserEmail: "b@example.com", Service: "linear", Type: storage.TokenTypeOAuth, UpdatedAt: now, ExpiresAt: now.Add(-time.Minute)},
		{UserEmail: "c@example.com", Service: "linear", Type: storage.TokenTypeOAuth, UpdatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{UserEmail: "c@example.com", Service: "notion", Type: storage.TokenTypeManual, UpdatedAt: now},
		{UserEmail: "d@example.com", Service: "linear", Type: storage.TokenTypeOAuth, UpdatedAt: now},
		{UserEmail: "e@example.com", Service: "github", Type: storage.TokenTypeManual, UpdatedAt: now},
	}

	page := buildConnectionsPage(columns, []string{"a@example.com", "z@example.com"}, tokens, now, "")

	assert.Equal(t, 6, page.TotalUsers)
	assert.Equal(t, 4, page.Columns[0].ConnectedCount)
	assert.Equal(t, 1, page.Columns[1].ConnectedCount)

	cell := func(email string, col int) ConnectionCellData {
		for _, row := range page.Rows {
			if row.UserEmail == email {
				return row.Cells[col]
			}
		}
		t.Fatalf("no row for %s", email)
		return ConnectionCellData{}
	}

	assert.Equal(t, ConnectionCellData{Connected: true, Expired: true, Refreshable: true}, cell("a@example.com", 0))
	assert.Equal(t, ConnectionCellData{Connected: true, Expired: true}, cell("b@example.com", 0))
	assert.Equal(t, ConnectionCellData{Connected: true}, cell("c@example.com", 0))
	assert.Equal(t, ConnectionCellData{Connected: true}, cell("c@example.com", 1))
	assert.False(t, cell("d@example.com", 0).Expired, "zero expiry never expires")
	assert.Equal(t, ConnectionCellData{}, cell("z@example.com", 0))
	assert.Equal(t, ConnectionCellData{}, cell("e@example.com", 0))

	require.Len(t, page.Orphans, 1)
	assert.Equal(t, OrphanedConnectionData{UserEmail: "e@example.com", Service: "github"}, page.Orphans[0])

	var emails []string
	for _, row := range page.Rows {
		emails = append(emails, row.UserEmail)
	}
	assert.Equal(t, []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "z@example.com"}, emails)

	filtered := buildConnectionsPage(columns, nil, tokens, now, "E@EX")
	assert.Len(t, filtered.Rows, 1)
	assert.Len(t, filtered.Orphans, 1)
	assert.Equal(t, 4, filtered.Columns[0].ConnectedCount, "totals ignore the filter")
}
