package aggregate

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/client"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientsSeeAConnectedServiceWithoutWaitingForTheCache(t *testing.T) {
	for _, gc := range gatewayClients {
		t.Run(gc.name, func(t *testing.T) {
			var connected atomic.Bool
			gw := startGateway(t, time.Hour, func(userEmail, backendName string) bool {
				return backendName == "linear" && connected.Load()
			})
			alice := gc.connect(t, gw, "alice@vori.com")
			require.Equal(t, []string{"docs.whoami"}, listToolNames(t, alice))

			relisted := make(chan struct{}, 16)
			alice.OnNotification(func(n mcp.JSONRPCNotification) {
				if n.Method == mcp.MethodNotificationToolsListChanged {
					relisted <- struct{}{}
				}
			})
			if gc.modern {
				stop, err := alice.ListenAsync(context.Background(), mcp.SubscriptionFilter{ToolsListChanged: true}, nil)
				require.NoError(t, err)
				t.Cleanup(stop)
			}
			awaitRelist := func() {
				t.Helper()
				select {
				case <-relisted:
				case <-time.After(5 * time.Second):
					t.Fatal("expected a tools/list_changed notification")
				}
			}

			connected.Store(true)
			gw.srv.UserTokenChanged("alice@vori.com", "linear")
			who, err := callWhoami(alice, "linear.whoami")
			require.NoError(t, err, "a call needs no prior tools/list")
			assert.Equal(t, "alice@vori.com", who)
			awaitRelist()
			assert.Equal(t, []string{"docs.whoami", "linear.whoami"}, listToolNames(t, alice))

			connected.Store(false)
			gw.srv.UserTokenChanged("alice@vori.com", "linear")
			awaitRelist()
			assert.Equal(t, []string{"docs.whoami"}, listToolNames(t, alice))
			_, err = callWhoami(alice, "linear.whoami")
			assert.ErrorContains(t, err, "not found")
		})
	}
}

func TestUserTokenChangedLeavesOtherUsersCachedViews(t *testing.T) {
	var mu sync.Mutex
	tokens := map[string]bool{"bob@vori.com": true}
	mocks := map[string]*mockTransport{
		"http://localhost/docs":   newMockTransport([]mcp.Tool{{Name: "search"}}),
		"http://localhost/linear": newMockTransport([]mcp.Tool{{Name: "list_issues"}}),
	}
	srv := NewServer(ServerConfig{
		Name: "gw",
		Backends: map[string]*config.MCPClientConfig{
			"docs":   {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/docs"},
			"linear": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/linear", RequiresUserToken: true},
		},
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: time.Hour},
		GetUserToken: func(_ context.Context, userEmail, _ string, _ *config.MCPClientConfig) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if !tokens[userEmail] {
				return "", storage.ErrUserTokenNotFound
			}
			return "token", nil
		},
		CreateTransport: func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
			if mock, ok := mocks[conf.URL]; ok {
				return mock, nil
			}
			return nil, fmt.Errorf("unknown backend %s", conf.URL)
		},
	})
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	viewTools := func(userEmail string) []string {
		srv.cacheMu.RLock()
		defer srv.cacheMu.RUnlock()
		return slices.Sorted(maps.Keys(srv.views[userEmail].tools))
	}

	srv.refreshView(context.Background(), "alice@vori.com")
	srv.refreshView(context.Background(), "bob@vori.com")
	require.Equal(t, []string{"docs.search"}, viewTools("alice@vori.com"))
	require.Equal(t, []string{"docs.search", "linear.list_issues"}, viewTools("bob@vori.com"))

	srv.cacheMu.RLock()
	bobView, bobCache := srv.views["bob@vori.com"], srv.userCache["bob@vori.com"]
	srv.cacheMu.RUnlock()

	mu.Lock()
	tokens["alice@vori.com"] = true
	mu.Unlock()
	srv.UserTokenChanged("alice@vori.com", "linear")

	srv.ensureView(context.Background(), "alice@vori.com")
	assert.Equal(t, []string{"docs.search", "linear.list_issues"}, viewTools("alice@vori.com"), "a tool call rebuilds a view built before the token changed")
	srv.ensureView(context.Background(), "bob@vori.com")

	srv.cacheMu.RLock()
	defer srv.cacheMu.RUnlock()
	assert.Same(t, bobView, srv.views["bob@vori.com"], "another user's view must not be rebuilt")
	assert.Same(t, bobCache, srv.userCache["bob@vori.com"], "another user's discovery must not be dropped")
}
