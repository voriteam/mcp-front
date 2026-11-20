package aggregate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stainless-api/mcp-front/internal/client"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/reqlog"
	"github.com/stainless-api/mcp-front/internal/storage"
	"github.com/stainless-api/mcp-front/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// mockTransport implements client.MCPClientInterface for testing.
// When Close() is called, all in-flight operations that select on closeCh
// will fail — matching real transport behavior where closing the underlying
// connection interrupts pending requests.
type mockTransport struct {
	mu            sync.Mutex
	tools         []mcp.Tool
	callToolFn    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
	initDelay     time.Duration
	listDelay     time.Duration
	started       bool
	initialized   bool
	closed        bool
	closeCh       chan struct{}
	startErr      error
	initializeErr error
	listToolsErr  error
}

func newMockTransport(tools []mcp.Tool) *mockTransport {
	return &mockTransport{
		tools:   tools,
		closeCh: make(chan struct{}),
	}
}

func (m *mockTransport) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.mu.Lock()
	m.started = true
	if m.closeCh == nil {
		m.closeCh = make(chan struct{})
	}
	m.mu.Unlock()
	return nil
}

func (m *mockTransport) Initialize(ctx context.Context, req mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	if m.initDelay > 0 {
		select {
		case <-time.After(m.initDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.initializeErr != nil {
		return nil, m.initializeErr
	}
	m.mu.Lock()
	m.initialized = true
	m.mu.Unlock()
	return &mcp.InitializeResult{}, nil
}

func (m *mockTransport) ListTools(ctx context.Context, req mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	if m.listDelay > 0 {
		select {
		case <-time.After(m.listDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m.mu.Lock()
	if err := m.listToolsErr; err != nil {
		m.mu.Unlock()
		return nil, err
	}
	tools := make([]mcp.Tool, len(m.tools))
	copy(tools, m.tools)
	m.mu.Unlock()
	return &mcp.ListToolsResult{Tools: tools}, nil
}

func (m *mockTransport) setListToolsErr(err error) {
	m.mu.Lock()
	m.listToolsErr = err
	m.mu.Unlock()
}

func (m *mockTransport) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if m.callToolFn != nil {
		return m.callToolFn(ctx, req)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent("ok")},
	}, nil
}

func (m *mockTransport) ListPrompts(ctx context.Context, req mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	return &mcp.ListPromptsResult{}, nil
}

func (m *mockTransport) GetPrompt(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{}, nil
}

func (m *mockTransport) ListResources(ctx context.Context, req mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	return &mcp.ListResourcesResult{}, nil
}

func (m *mockTransport) ReadResource(ctx context.Context, req mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{}, nil
}

func (m *mockTransport) ListResourceTemplates(ctx context.Context, req mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	return &mcp.ListResourceTemplatesResult{}, nil
}

func (m *mockTransport) Ping(ctx context.Context) error { return nil }

// slowInitTransport wraps mockTransport with a controllable Initialize delay
// for testing singleflight context propagation.
type slowInitTransport struct {
	*mockTransport
	initStarted chan struct{}
	initProceed chan struct{}
}

func (s *slowInitTransport) Initialize(ctx context.Context, req mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	select {
	case s.initStarted <- struct{}{}:
	default:
	}
	select {
	case <-s.initProceed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.mockTransport.Initialize(ctx, req)
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	alreadyClosed := m.closed
	m.closed = true
	m.mu.Unlock()
	if !alreadyClosed && m.closeCh != nil {
		close(m.closeCh)
	}
	return nil
}

func (m *mockTransport) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// newTestServer creates a Server for testing with mock transports.
func newTestServer(t *testing.T, backends map[string]*mockTransport) *Server {
	t.Helper()
	return newTestServerWith(t, backends, func(*ServerConfig) {})
}

func newTestServerWith(t *testing.T, backends map[string]*mockTransport, configure func(*ServerConfig)) *Server {
	t.Helper()

	backendConfigs := make(map[string]*config.MCPClientConfig, len(backends))
	for name := range backends {
		backendConfigs[name] = &config.MCPClientConfig{
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/" + name,
		}
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		for name, mock := range backends {
			if conf.URL == "http://localhost/"+name {
				return mock, nil
			}
		}
		return nil, fmt.Errorf("unknown backend")
	}

	getUserToken := func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
		return "", nil
	}

	cfg := ServerConfig{
		Name:            "test-aggregate",
		Backends:        backendConfigs,
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken:    getUserToken,
		CreateTransport: factory,
	}
	configure(&cfg)
	srv := NewServer(cfg)
	srv.Start()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	return srv
}

func TestDiscoverTools(t *testing.T) {
	pgTools := []mcp.Tool{
		{Name: "query", Description: "Run SQL query"},
		{Name: "tables", Description: "List tables"},
	}
	linearTools := []mcp.Tool{
		{Name: "create_issue", Description: "Create issue"},
	}

	backends := map[string]*mockTransport{
		"postgres": {tools: pgTools},
		"linear":   {tools: linearTools},
	}

	srv := newTestServer(t, backends)

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	totalTools := 0
	for _, bt := range tools {
		totalTools += len(bt)
	}
	assert.Equal(t, 3, totalTools)
	assert.Len(t, tools["postgres"], 2)
	assert.Len(t, tools["linear"], 1)
	assert.Equal(t, "Run SQL query", tools["postgres"][0].Description)
}

func TestDiscoverToolsCaching(t *testing.T) {
	var callCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	mock := &mockTransport{tools: []mcp.Tool{{Name: "query"}}}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		callCount.Add(1)
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	_, err = srv.getTools(context.Background(), "other@test.com")
	require.NoError(t, err)
	// Second call uses cache — no new transport created
	assert.Equal(t, int32(1), callCount.Load())
}

// TestPerUserTokenBackendIsolation verifies that a backend requiring a user
// token is discovered per-user: a user without a token never sees it, a user
// with one does, and neither user's discovery leaks into the other's tool set.
func TestToolHandlerRejectsToolsOutsideTheCallersView(t *testing.T) {
	var called atomic.Bool
	gated := newMockTransport([]mcp.Tool{{Name: "catalog"}})
	gated.callToolFn = func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called.Store(true)
		return mcp.NewToolResultText("catalog"), nil
	}
	srv := NewServer(ServerConfig{
		Name: "test-aggregate",
		Backends: map[string]*config.MCPClientConfig{"materialize": {
			TransportType:     config.MCPClientTypeSSE,
			URL:               "http://localhost/materialize",
			RequiresUserToken: true,
		}},
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: time.Minute},
		GetUserToken: func(_ context.Context, userEmail, _ string, _ *config.MCPClientConfig) (string, error) {
			if userEmail == "alice@test.com" {
				return "alice-token", nil
			}
			return "", storage.ErrUserTokenNotFound
		},
		CreateTransport: func(*config.MCPClientConfig) (client.MCPClientInterface, error) { return gated, nil },
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	ctx := context.Background()
	srv.refreshView(ctx, "alice@test.com")
	srv.refreshView(ctx, "bob@test.com")
	require.NotNil(t, srv.mcpServer.GetTool("materialize.catalog"), "alice's discovery registers the tool for everyone")

	bobCtx := context.WithValue(ctx, oauth.GetUserContextKey(), "bob@test.com")
	_, err := srv.callTool(bobCtx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "materialize.catalog"}})
	require.ErrorIs(t, err, mcpserver.ErrToolNotFound)
	assert.False(t, called.Load(), "bob's call must not reach the backend")

	strangerCtx := context.WithValue(ctx, oauth.GetUserContextKey(), "stranger@test.com")
	_, err = srv.callTool(strangerCtx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "materialize.catalog"}})
	require.ErrorIs(t, err, mcpserver.ErrToolNotFound)
	assert.False(t, called.Load(), "a caller with no view must not reach the backend")
}

func TestPerUserTokenBackendIsolation(t *testing.T) {
	sharedMock := newMockTransport([]mcp.Tool{{Name: "query"}})
	tokenMock := newMockTransport([]mcp.Tool{{Name: "catalog"}})

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/postgres",
		},
		"materialize": {
			TransportType:     config.MCPClientTypeSSE,
			URL:               "http://localhost/materialize",
			RequiresUserToken: true,
		},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		switch conf.URL {
		case "http://localhost/postgres":
			return sharedMock, nil
		case "http://localhost/materialize":
			return tokenMock, nil
		}
		return nil, fmt.Errorf("unknown backend")
	}

	// Only alice has a materialize token.
	getUserToken := func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
		if userEmail == "alice@test.com" && serviceName == "materialize" {
			return "alice-token", nil
		}
		return "", nil
	}

	srv := NewServer(ServerConfig{
		Name:            "test-aggregate",
		Backends:        backendConfigs,
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken:    getUserToken,
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Bob (no materialize token) discovers first: shared backend visible,
	// token-gated backend not.
	bobTools, err := srv.getTools(context.Background(), "bob@test.com")
	require.NoError(t, err)
	assert.Len(t, bobTools["postgres"], 1, "bob should see the shared backend")
	assert.NotContains(t, bobTools, "materialize", "bob has no token, must not see materialize")

	// Alice discovers next: bob's tokenless discovery must not have cached an
	// absence of materialize for everyone — alice still sees it.
	aliceTools, err := srv.getTools(context.Background(), "alice@test.com")
	require.NoError(t, err)
	assert.Len(t, aliceTools["postgres"], 1, "alice should see the shared backend")
	assert.Len(t, aliceTools["materialize"], 1, "alice has a token, must see materialize")

	// Bob again: alice's token-gated tools must not leak into bob's set.
	bobTools, err = srv.getTools(context.Background(), "bob@test.com")
	require.NoError(t, err)
	assert.NotContains(t, bobTools, "materialize", "alice's token-gated tools must not leak to bob")
}

func TestDiscoverToolsTimeout(t *testing.T) {
	backends := map[string]*mockTransport{
		"fast": {tools: []mcp.Tool{{Name: "fast_tool"}}},
		"slow": {tools: []mcp.Tool{{Name: "slow_tool"}}, initDelay: 10 * time.Second},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"fast": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/fast"},
		"slow": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/slow"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		for name, mock := range backends {
			if conf.URL == "http://localhost/"+name {
				return mock, nil
			}
		}
		return nil, fmt.Errorf("unknown backend")
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 100 * time.Millisecond, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Contains(t, tools, "fast")
	assert.NotContains(t, tools, "slow")
}

func TestToolRouting(t *testing.T) {
	var calledWithName string
	pgMock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
		callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calledWithName = req.Params.Name
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.NewTextContent("result")},
			}, nil
		},
	}

	backends := map[string]*mockTransport{
		"postgres": pgMock,
	}

	srv := newTestServer(t, backends)

	handler := toolHandlerAs(srv, "user@test.com")
	result, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "postgres.query",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "query", calledWithName)
	assert.Len(t, result.Content, 1)
}

func toolHandlerAs(srv *Server, userEmail string) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		srv.ensureView(ctx, userEmail)
		return srv.callTool(context.WithValue(ctx, oauth.GetUserContextKey(), userEmail), req)
	}
}

func whoamiBackend(t *testing.T) string {
	t.Helper()
	backendMCP := mcpserver.NewMCPServer("backend", "1.0.0", mcpserver.WithToolCapabilities(true))
	backendMCP.AddTool(mcp.NewTool("whoami"), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(req.Header.Get("X-User")), nil
	})
	backend := httptest.NewServer(mcpserver.NewStreamableHTTPServer(backendMCP, mcpserver.WithEndpointPath("/")))
	t.Cleanup(backend.Close)
	return backend.URL + "/"
}

type testGateway struct {
	srv     *Server
	url     string
	methods func() []string
}

// startGateway serves a gateway over a shared docs backend and two token-gated
// backends, linear and hubspot, each answering whoami with the caller's email.
func startGateway(t *testing.T, cacheTTL time.Duration, connected func(userEmail, backendName string) bool) testGateway {
	t.Helper()
	backend := func(requiresUserToken bool) *config.MCPClientConfig {
		return &config.MCPClientConfig{
			TransportType:     config.MCPClientTypeStreamable,
			URL:               whoamiBackend(t),
			Headers:           map[string]string{"X-User": "{{email}}"},
			HeadersNeedEmail:  map[string]bool{"X-User": true},
			RequiresUserToken: requiresUserToken,
		}
	}
	srv := NewServer(ServerConfig{
		Name: "gw",
		Backends: map[string]*config.MCPClientConfig{
			"docs":    backend(false),
			"linear":  backend(true),
			"hubspot": backend(true),
		},
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: cacheTTL},
		GetUserToken: func(_ context.Context, userEmail, backendName string, _ *config.MCPClientConfig) (string, error) {
			if connected(userEmail, backendName) {
				return "token", nil
			}
			return "", storage.ErrUserTokenNotFound
		},
		CreateTransport: client.DefaultTransportCreator,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	var mu sync.Mutex
	var methods []string
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var msg struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(body, &msg)
			mu.Lock()
			methods = append(methods, msg.Method)
			mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		ctx := context.WithValue(r.Context(), oauth.GetUserContextKey(), r.Header.Get("X-Test-User"))
		srv.Handler().ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(front.Close)

	return testGateway{srv: srv, url: front.URL, methods: func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(methods)
	}}
}

type gatewayClient struct {
	name   string
	modern bool
}

var gatewayClients = []gatewayClient{
	{name: "sessionless", modern: true},
	{name: "session"},
}

func (gc gatewayClient) connect(t *testing.T, gw testGateway, userEmail string) *mcpclient.Client {
	t.Helper()
	ctx := context.Background()
	headers := map[string]string{"X-Test-User": userEmail}
	trOpts := []transport.StreamableHTTPCOption{transport.WithHTTPHeaders(headers)}
	if !gc.modern {
		//lint:ignore SA1019 session-based clients still receive notifications on the GET stream
		trOpts = append(trOpts, transport.WithContinuousListening()) //nolint:staticcheck
	}
	tr, err := transport.NewStreamableHTTP(gw.url+"/gw/", trOpts...)
	require.NoError(t, err)

	var opts []mcpclient.ClientOption
	if !gc.modern {
		opts = append(opts, mcpclient.WithProtocolVersion(mcp.LATEST_LEGACY_PROTOCOL_VERSION))
	}
	c := mcpclient.NewClient(tr, opts...)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.Initialize(ctx, mcp.InitializeRequest{Params: mcp.InitializeParams{
		ClientInfo: mcp.Implementation{Name: "test", Version: "1"},
	}})
	require.NoError(t, err)
	return c
}

func listToolNames(t *testing.T, c *mcpclient.Client) []string {
	t.Helper()
	result, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	require.NoError(t, err)
	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func callWhoami(c *mcpclient.Client, tool string) (string, error) {
	result, err := c.CallTool(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: tool}})
	if err != nil {
		return "", err
	}
	if len(result.Content) != 1 {
		return "", fmt.Errorf("unexpected content: %v", result.Content)
	}
	return result.Content[0].(mcp.TextContent).Text, nil
}

func TestGatewayIsolatesUsers(t *testing.T) {
	connected := map[string]string{"alice@vori.com": "linear", "bob@vori.com": "hubspot"}
	for _, gc := range gatewayClients {
		t.Run(gc.name, func(t *testing.T) {
			gw := startGateway(t, time.Minute, func(userEmail, backendName string) bool {
				return connected[userEmail] == backendName
			})
			alice, bob := gc.connect(t, gw, "alice@vori.com"), gc.connect(t, gw, "bob@vori.com")

			assert.Equal(t, []string{"docs.whoami", "hubspot.whoami"}, listToolNames(t, bob))

			who, err := callWhoami(alice, "linear.whoami")
			require.NoError(t, err, "a call needs no prior tools/list")
			assert.Equal(t, "alice@vori.com", who)

			assert.Equal(t, []string{"docs.whoami", "linear.whoami"}, listToolNames(t, alice))

			for c, want := range map[*mcpclient.Client]string{alice: "alice@vori.com", bob: "bob@vori.com"} {
				who, err := callWhoami(c, "docs.whoami")
				require.NoError(t, err)
				assert.Equal(t, want, who)
			}
			who, err = callWhoami(bob, "hubspot.whoami")
			require.NoError(t, err)
			assert.Equal(t, "bob@vori.com", who)

			_, err = callWhoami(alice, "hubspot.whoami")
			assert.ErrorContains(t, err, "not found")
			_, err = callWhoami(bob, "linear.whoami")
			assert.ErrorContains(t, err, "not found")
		})
	}
}

func TestSessionlessClientSkipsInitialize(t *testing.T) {
	gw := startGateway(t, time.Minute, func(string, string) bool { return false })
	c := gatewayClients[0].connect(t, gw, "alice@vori.com")

	assert.Equal(t, []string{"docs.whoami"}, listToolNames(t, c))
	assert.Empty(t, c.GetSessionId())
	assert.Equal(t, []string{"server/discover", "tools/list"}, gw.methods())
}

func TestClientsRelistWhenTheirToolsChange(t *testing.T) {
	for _, gc := range gatewayClients {
		t.Run(gc.name, func(t *testing.T) {
			var bobConnected atomic.Bool
			gw := startGateway(t, 50*time.Millisecond, func(userEmail, backendName string) bool {
				return backendName == "linear" && (userEmail == "alice@vori.com" || bobConnected.Load())
			})
			alice, bob := gc.connect(t, gw, "alice@vori.com"), gc.connect(t, gw, "bob@vori.com")
			require.Equal(t, []string{"docs.whoami", "linear.whoami"}, listToolNames(t, alice))
			require.Equal(t, []string{"docs.whoami"}, listToolNames(t, bob))

			relisted := make(chan struct{}, 16)
			bob.OnNotification(func(n mcp.JSONRPCNotification) {
				if n.Method == mcp.MethodNotificationToolsListChanged {
					relisted <- struct{}{}
				}
			})
			if gc.modern {
				stop, err := bob.ListenAsync(context.Background(), mcp.SubscriptionFilter{ToolsListChanged: true}, nil)
				require.NoError(t, err)
				t.Cleanup(stop)
			}

			time.Sleep(200 * time.Millisecond)
			_, err := callWhoami(bob, "docs.whoami")
			require.NoError(t, err)
			select {
			case <-relisted:
				t.Fatal("unchanged tools must not ask clients to re-list")
			case <-time.After(300 * time.Millisecond):
			}

			bobConnected.Store(true)
			time.Sleep(100 * time.Millisecond)
			_, err = callWhoami(bob, "docs.whoami")
			require.NoError(t, err)
			select {
			case <-relisted:
			case <-time.After(5 * time.Second):
				t.Fatal("expected a tools/list_changed notification")
			}
			assert.Equal(t, []string{"docs.whoami", "linear.whoami"}, listToolNames(t, bob))
		})
	}
}

func discoverFromBackend(t *testing.T, tools string) (discovered []mcp.Tool, backendMethods []string) {
	t.Helper()
	var mu sync.Mutex
	var methods []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, req.Method)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		result := map[string]any{}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "backend-session")
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "legacy", "version": "1"},
			}
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
			result = map[string]any{"tools": json.RawMessage(tools)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(backend.Close)

	srv := NewServer(ServerConfig{
		Name:            "gw",
		Backends:        map[string]*config.MCPClientConfig{"backend": {TransportType: config.MCPClientTypeStreamable, URL: backend.URL}},
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		CreateTransport: client.DefaultTransportCreator,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	byBackend, err := srv.ListToolsByBackend(context.Background(), "user@vori.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	return byBackend["backend"], slices.Clone(methods)
}

func TestBackendConnectionsOpenWithInitialize(t *testing.T) {
	_, methods := discoverFromBackend(t, `[{"name":"query","inputSchema":{"type":"object"}}]`)
	assert.Equal(t, []string{"initialize", "notifications/initialized", "tools/list"}, methods)
}

func TestDiscoveryKeepsArrayValuedSchemaTypes(t *testing.T) {
	tools, _ := discoverFromBackend(t, `[{
		"name": "list_commits",
		"inputSchema": {"type": ["object", "null"], "properties": {"owner": {"type": "string"}}},
		"outputSchema": {"type": ["null", "object"], "properties": {"sha": {"type": "string"}}}
	}]`)
	require.Len(t, tools, 1)

	encoded, err := json.Marshal(tools[0])
	require.NoError(t, err)
	var schemas struct {
		InputSchema  struct{ Type []string } `json:"inputSchema"`
		OutputSchema struct{ Type []string } `json:"outputSchema"`
	}
	require.NoError(t, json.Unmarshal(encoded, &schemas))
	assert.Equal(t, []string{"object", "null"}, schemas.InputSchema.Type)
	assert.Equal(t, []string{"null", "object"}, schemas.OutputSchema.Type)
}

func TestPerUserConnectionIsolation(t *testing.T) {
	var connCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		connCount.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	conn1, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	conn2, err := srv.getOrCreateConn(context.Background(), "bob@test.com", "postgres")
	require.NoError(t, err)

	assert.NotSame(t, conn1, conn2)
	assert.Equal(t, int32(2), connCount.Load())
}

func TestConnectionReuse(t *testing.T) {
	var connCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		connCount.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	conn1, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	conn2, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	assert.Same(t, conn1, conn2)
	assert.Equal(t, int32(1), connCount.Load())
}

func TestShutdownClosesConnections(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()

	_, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)

	assert.True(t, mock.isClosed())
}

func TestToolFilter(t *testing.T) {
	pgMock := &mockTransport{
		tools: []mcp.Tool{
			{Name: "query"},
			{Name: "dangerous_drop"},
			{Name: "tables"},
		},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/postgres",
			Options: &config.Options{
				ToolFilter: &config.ToolFilterConfig{
					Mode: config.ToolFilterModeBlock,
					List: []string{"dangerous_drop"},
				},
			},
		},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return pgMock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	pgTools := tools["postgres"]
	names := make([]string, len(pgTools))
	for i, tool := range pgTools {
		names[i] = tool.Name
	}

	assert.Contains(t, names, "query")
	assert.Contains(t, names, "tables")
	assert.NotContains(t, names, "dangerous_drop")
}

func TestDiscoverySurvivesCallerCancellation(t *testing.T) {
	initStarted := make(chan struct{})
	initProceed := make(chan struct{})

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	var factoryCalls atomic.Int32
	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		return &slowInitTransport{
			mockTransport: &mockTransport{
				tools: []mcp.Tool{{Name: "query"}},
			},
			initStarted: initStarted,
			initProceed: initProceed,
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	callerCtx, callerCancel := context.WithCancel(context.Background())

	type toolResult struct {
		tools map[string][]mcp.Tool
		err   error
	}
	caller1Done := make(chan toolResult, 1)
	caller2Done := make(chan toolResult, 1)

	go func() {
		tools, err := srv.getTools(callerCtx, "user1@test.com")
		caller1Done <- toolResult{tools, err}
	}()
	go func() {
		tools, err := srv.getTools(context.Background(), "user2@test.com")
		caller2Done <- toolResult{tools, err}
	}()

	<-initStarted
	callerCancel()
	close(initProceed)

	r1 := <-caller1Done
	r2 := <-caller2Done

	// Both should succeed — context.WithoutCancel prevents caller1's
	// cancellation from killing the shared singleflight discovery.
	require.NoError(t, r2.err, "caller2 with Background context should succeed")
	assert.Len(t, r2.tools["postgres"], 1)

	// caller1 also succeeds because WithoutCancel detaches cancellation
	require.NoError(t, r1.err, "caller1 should also succeed (singleflight shares result)")
	assert.Len(t, r1.tools["postgres"], 1)

	// Only one transport should have been created (singleflight dedup)
	assert.Equal(t, int32(1), factoryCalls.Load())
}

func TestConcurrentGetOrCreateConn(t *testing.T) {
	var factoryCalls atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	const goroutines = 10
	var wg sync.WaitGroup
	conns := make([]*conn, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}
	for i := 1; i < goroutines; i++ {
		assert.Same(t, conns[0], conns[i], "all goroutines should get the same conn")
	}
	assert.Equal(t, int32(1), factoryCalls.Load(), "singleflight should create exactly one transport")
}

func TestDoubleShutdown(t *testing.T) {
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	}
	srv := newTestServer(t, backends)

	err := srv.Shutdown(context.Background())
	require.NoError(t, err)

	// Second shutdown must not panic
	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestAllBackendsFail(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"broken": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/broken"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return nil, fmt.Errorf("connection refused")
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all backends failed")
}

func TestEvictConnOnListToolsFailure(t *testing.T) {
	var factoryCalls atomic.Int32
	var failOnList atomic.Bool
	failOnList.Store(true)

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		mock := &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}
		if failOnList.Load() {
			mock.listToolsErr = fmt.Errorf("connection reset")
		}
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// First discovery: ListTools fails, connection should be evicted
	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Equal(t, int32(1), factoryCalls.Load())

	// Verify connection was evicted from the pool
	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "postgres"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")

	// Fix the backend and retry — should create a new connection
	failOnList.Store(false)
	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Equal(t, int32(2), factoryCalls.Load(), "should have created a fresh connection")
	assert.Len(t, tools["postgres"], 1)
}

func TestEvictConnOnCallToolFailure(t *testing.T) {
	var callCount atomic.Int32
	pgMock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
		callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			n := callCount.Add(1)
			if n == 1 {
				return nil, fmt.Errorf("connection reset")
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.NewTextContent("ok")},
			}, nil
		},
	}

	backends := map[string]*mockTransport{
		"postgres": pgMock,
	}
	srv := newTestServer(t, backends)

	handler := toolHandlerAs(srv, "user@test.com")

	// First call fails with transport error — connection should be evicted
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres.query"},
	})
	require.Error(t, err)

	// Verify eviction happened
	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "postgres"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")
}

// countingTokenSource is a fake oauth2.TokenSource that records how many times
// a token was minted, standing in for a client-credentials source.
type countingTokenSource struct{ calls atomic.Int32 }

func (c *countingTokenSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	return &oauth2.Token{AccessToken: "test-token", TokenType: "Bearer"}, nil
}

// TestRetryOnAuthErrorRemintsToken simulates a client-credentials backend whose
// pooled connection carries an expired bearer: the first discovery returns a 401,
// and the fix must recreate the connection (re-minting the token) and retry
// instead of evicting the backend out of the aggregated tool list.
func TestRetryOnAuthErrorRemintsToken(t *testing.T) {
	var factoryCalls atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"help-docs": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/help-docs"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		n := factoryCalls.Add(1)
		mock := &mockTransport{tools: []mcp.Tool{{Name: "search"}}}
		if n == 1 {
			mock.listToolsErr = transport.ErrAuthorizationRequired
		}
		return mock, nil
	}

	tokens := &countingTokenSource{}
	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		TokenSources:    map[string]oauth2.TokenSource{"help-docs": tokens},
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["help-docs"], 1, "backend should stay available after the auth-error retry")
	assert.Equal(t, int32(2), factoryCalls.Load(), "connection should be recreated exactly once")
	assert.GreaterOrEqual(t, tokens.calls.Load(), int32(2), "a fresh token should be minted for the new connection")
}

// TestRetryOnAuthErrorToolCall covers the same recovery on the tool-call path.
func TestRetryOnAuthErrorToolCall(t *testing.T) {
	var factoryCalls atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"help-docs": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/help-docs"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		n := factoryCalls.Add(1)
		mock := &mockTransport{tools: []mcp.Tool{{Name: "search"}}}
		if n == 1 {
			mock.callToolFn = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, transport.ErrAuthorizationRequired
			}
		}
		return mock, nil
	}

	tokens := &countingTokenSource{}
	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		TokenSources:    map[string]oauth2.TokenSource{"help-docs": tokens},
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	handler := toolHandlerAs(srv, "user@test.com")
	result, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "help-docs.search"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int32(2), factoryCalls.Load(), "connection should be recreated exactly once")

	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "help-docs"}]
	srv.connMu.RUnlock()
	assert.True(t, exists, "healthy connection should remain pooled after the retry")
}

// TestAuthErrorNotRetriedWithoutCredential locks the gating: a 401 from a backend
// with no re-mintable credential is returned after a single attempt rather than
// retried pointlessly with the same rejected bearer.
func TestAuthErrorNotRetriedWithoutCredential(t *testing.T) {
	var factoryCalls atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"public": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/public"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		mock := &mockTransport{tools: []mcp.Tool{{Name: "ping"}}}
		mock.listToolsErr = transport.ErrAuthorizationRequired
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Equal(t, int32(1), factoryCalls.Load(), "auth error without a refreshable credential must not be retried")

	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "public"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")
}

func TestGetUserTokenFailureDegradation(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {
			TransportType:     config.MCPClientTypeSSE,
			URL:               "http://localhost/postgres",
			RequiresUserToken: true,
		},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	var tokenCallCount atomic.Int32
	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			tokenCallCount.Add(1)
			return "", fmt.Errorf("token store unavailable")
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Connection should succeed despite token failure — createConn logs
	// the warning and proceeds without the token.
	c, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, int32(1), tokenCallCount.Load())

	// The connection should be functional
	assert.True(t, mock.started)
}

func TestShutdownDuringActiveToolCall(t *testing.T) {
	toolStarted := make(chan struct{})

	pgMock := newMockTransport([]mcp.Tool{{Name: "query"}})
	pgMock.callToolFn = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		close(toolStarted)
		// Block until the transport is closed (simulating real behavior where
		// closing the underlying HTTP connection interrupts in-flight requests)
		// or the caller context is done.
		select {
		case <-pgMock.closeCh:
			return nil, fmt.Errorf("transport closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return pgMock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()

	// Establish connection first
	_, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)

	// Start a tool call that blocks
	handler := toolHandlerAs(srv, "user@test.com")
	type callResult struct {
		result *mcp.CallToolResult
		err    error
	}
	done := make(chan callResult, 1)
	go func() {
		r, err := handler(context.Background(), mcp.CallToolRequest{
			Params: mcp.CallToolParams{Name: "postgres.query"},
		})
		done <- callResult{r, err}
	}()

	// Wait for tool call to be in-flight
	<-toolStarted

	// Shutdown while tool call is active — Close() on the transport
	// closes closeCh, which unblocks the in-flight CallTool.
	shutdownErr := srv.Shutdown(context.Background())
	require.NoError(t, shutdownErr)

	// The in-flight tool call should complete with an error
	result := <-done
	assert.Error(t, result.err, "in-flight tool call should fail after shutdown")
}

func TestCacheExpiryAndRediscovery(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 50 * time.Millisecond},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// First discovery
	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 1)
	assert.Equal(t, "query", tools["postgres"][0].Name)

	// Simulate backend adding a new tool — mutate the mock directly so the
	// existing connection (reused on rediscovery) returns updated tools.
	mock.mu.Lock()
	mock.tools = []mcp.Tool{
		{Name: "query"},
		{Name: "tables"},
	}
	mock.mu.Unlock()

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Rediscovery should pick up the new tool
	tools, err = srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 2)
}

func TestMaxConnsPerUser(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"backend1": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend1"},
		"backend2": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend2"},
		"backend3": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend3"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return &mockTransport{tools: []mcp.Tool{{Name: "tool"}}}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second, MaxConnsPerUser: 2},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "backend1")
	require.NoError(t, err)
	_, err = srv.getOrCreateConn(context.Background(), "alice@test.com", "backend2")
	require.NoError(t, err)

	// Third connection exceeds limit
	_, err = srv.getOrCreateConn(context.Background(), "alice@test.com", "backend3")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserConnLimitExceeded)

	// Different user is unaffected
	_, err = srv.getOrCreateConn(context.Background(), "bob@test.com", "backend1")
	require.NoError(t, err)
}

func TestMaxConnsPerUserZeroUnlimited(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"b1": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b1"},
		"b2": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b2"},
		"b3": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b3"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return &mockTransport{tools: []mcp.Tool{{Name: "tool"}}}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second, MaxConnsPerUser: 0},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	for _, name := range []string{"b1", "b2", "b3"} {
		_, err := srv.getOrCreateConn(context.Background(), "alice@test.com", name)
		require.NoError(t, err, "connection to %s should succeed with unlimited pool", name)
	}
}

type staticTokenSource struct{ token string }

func (s staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token, TokenType: "Bearer"}, nil
}

func TestTokenSourceAppliedToBackendConfig(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"mintlify": {
			TransportType: config.MCPClientTypeStreamable,
			URL:           "http://localhost/mintlify",
			Headers:       map[string]string{"X-Existing": "keep"},
		},
		"plain": {
			TransportType: config.MCPClientTypeStreamable,
			URL:           "http://localhost/plain",
		},
	}

	var (
		mu   sync.Mutex
		seen = make(map[string]map[string]string)
	)
	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		mu.Lock()
		headers := make(map[string]string, len(conf.Headers))
		for k, v := range conf.Headers {
			headers[k] = v
		}
		for name, bc := range backendConfigs {
			if conf.URL == bc.URL {
				seen[name] = headers
			}
		}
		mu.Unlock()
		return &mockTransport{tools: []mcp.Tool{{Name: "tool"}}}, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		TokenSources:    map[string]oauth2.TokenSource{"mintlify": staticTokenSource{"secret-access-token"}},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "mintlify")
	require.NoError(t, err)
	_, err = srv.getOrCreateConn(context.Background(), "alice@test.com", "plain")
	require.NoError(t, err)

	assert.Equal(t, "Bearer secret-access-token", seen["mintlify"]["Authorization"])
	assert.Equal(t, "keep", seen["mintlify"]["X-Existing"])
	assert.NotContains(t, seen["plain"], "Authorization", "backends without a token source get no Authorization header")

	// Original backend config map must not be mutated.
	assert.NotContains(t, backendConfigs["mintlify"].Headers, "Authorization")
}

// TestRetryOnSessionInvalidation verifies that when a backend rejects a pooled
// connection's expired session, the aggregate transparently re-initializes a
// fresh connection and retries the tool call instead of surfacing the error.
func TestRetryOnSessionInvalidation(t *testing.T) {
	// Both forms mcp-go can surface: an HTTP 404 mapped to ErrSessionTerminated,
	// and a 4xx whose body carries the reason (e.g. Datadog's "Invalid session ID").
	cases := map[string]error{
		"terminated_404":     transport.ErrSessionTerminated,
		"invalid_session_id": fmt.Errorf("request failed with status 400: Invalid session ID"),
	}

	for name, sessionErr := range cases {
		t.Run(name, func(t *testing.T) {
			var factoryCalls atomic.Int32
			var callCount atomic.Int32

			backendConfigs := map[string]*config.MCPClientConfig{
				"datadog": {TransportType: config.MCPClientTypeStreamable, URL: "http://localhost/datadog"},
			}

			factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
				factoryCalls.Add(1)
				return &mockTransport{
					tools: []mcp.Tool{{Name: "search"}},
					callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
						if callCount.Add(1) == 1 {
							return nil, sessionErr
						}
						return &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent("ok")}}, nil
					},
				}, nil
			}

			srv := NewServer(ServerConfig{
				Name:      "test-aggregate",
				Backends:  backendConfigs,
				Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
				GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
					return "", nil
				},
				CreateTransport: factory,
			})
			srv.Start()
			t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

			handler := toolHandlerAs(srv, "user@test.com")
			result, err := handler(context.Background(), mcp.CallToolRequest{
				Params: mcp.CallToolParams{Name: "datadog.search"},
			})
			require.NoError(t, err, "session error should be recovered transparently")
			require.NotNil(t, result)
			assert.False(t, result.IsError)
			assert.Equal(t, int32(2), callCount.Load(), "CallTool should have been retried exactly once")
			assert.Equal(t, int32(2), factoryCalls.Load(), "retry should re-initialize a fresh connection")

			// A healthy connection should remain pooled after the successful retry.
			srv.connMu.RLock()
			_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "datadog"}]
			srv.connMu.RUnlock()
			assert.True(t, exists, "healthy connection should stay pooled after retry")
		})
	}
}

// TestNoRetryOnNonSessionError verifies that a non-session transport error is
// not retried: the connection is evicted and the error is returned once.
func TestNoRetryOnNonSessionError(t *testing.T) {
	var callCount atomic.Int32
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "search"}},
		callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			callCount.Add(1)
			return nil, fmt.Errorf("connection reset")
		},
	}
	srv := newTestServer(t, map[string]*mockTransport{"datadog": mock})

	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "datadog.search"},
	})
	require.Error(t, err)
	assert.Equal(t, int32(1), callCount.Load(), "non-session error must not be retried")

	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "datadog"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")
}

// TestRetryOnSessionInvalidationDuringDiscovery verifies the retry also covers
// the tool-discovery (ListTools) path, and that a retry does not accumulate
// duplicate tools onto the partial result from the failed first attempt.
func TestRetryOnSessionInvalidationDuringDiscovery(t *testing.T) {
	var factoryCalls atomic.Int32
	var listCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"datadog": {TransportType: config.MCPClientTypeStreamable, URL: "http://localhost/datadog"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		mock := &mockTransport{tools: []mcp.Tool{{Name: "search"}}}
		if listCount.Add(1) == 1 {
			mock.listToolsErr = transport.ErrSessionTerminated
		}
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err, "session error during discovery should be recovered")
	assert.Len(t, tools["datadog"], 1, "retry must not duplicate tools from the failed attempt")
	assert.Equal(t, int32(2), factoryCalls.Load(), "retry should re-initialize a fresh connection")
}

// errTransientDiscovery is a transport-level failure, not an auth rejection.
var errTransientDiscovery = errors.New("transport error: context deadline exceeded")

// newStaleToolsTestServer builds an aggregate with a caller-supplied discovery
// config so tests can drive cache expiry directly.
func newStaleToolsTestServer(t *testing.T, backends map[string]*mockTransport, disc *config.DiscoveryConfig) *Server {
	t.Helper()

	backendConfigs := make(map[string]*config.MCPClientConfig, len(backends))
	for name := range backends {
		backendConfigs[name] = &config.MCPClientConfig{
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/" + name,
		}
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		for name, mock := range backends {
			if conf.URL == "http://localhost/"+name {
				return mock, nil
			}
		}
		return nil, fmt.Errorf("unknown backend")
	}

	srv := NewServer(ServerConfig{
		Name:      "test-aggregate",
		Backends:  backendConfigs,
		Discovery: disc,
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv
}

func TestDiscoveryServesLastKnownToolsOnTransientFailure(t *testing.T) {
	linear := &mockTransport{tools: []mcp.Tool{{Name: "create_issue"}}}
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
		"linear":   linear,
	}
	srv := newStaleToolsTestServer(t, backends, &config.DiscoveryConfig{
		Timeout:  5 * time.Second,
		CacheTTL: 10 * time.Millisecond,
	})

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	require.Len(t, tools["linear"], 1)

	linear.setListToolsErr(errTransientDiscovery)
	time.Sleep(30 * time.Millisecond)

	tools, err = srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 1, "healthy backend still discovered")
	require.Len(t, tools["linear"], 1, "failing backend served from its last successful discovery")
	assert.Equal(t, "create_issue", tools["linear"][0].Name)
}

func TestDiscoveryDropsBackendOnAuthFailure(t *testing.T) {
	linear := &mockTransport{tools: []mcp.Tool{{Name: "create_issue"}}}
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
		"linear":   linear,
	}
	srv := newStaleToolsTestServer(t, backends, &config.DiscoveryConfig{
		Timeout:  5 * time.Second,
		CacheTTL: 10 * time.Millisecond,
	})

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	require.Len(t, tools["linear"], 1)

	linear.setListToolsErr(transport.ErrAuthorizationRequired)
	time.Sleep(30 * time.Millisecond)

	tools, err = srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 1)
	assert.Empty(t, tools["linear"], "backend rejected for auth is dropped, not served stale")
}

func TestPartialDiscoveryIsCachedBriefly(t *testing.T) {
	linear := &mockTransport{tools: []mcp.Tool{{Name: "create_issue"}}}
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
		"linear":   linear,
	}
	srv := newStaleToolsTestServer(t, backends, &config.DiscoveryConfig{
		Timeout:  5 * time.Second,
		CacheTTL: time.Hour,
	})

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	srv.cacheMu.RLock()
	fullExpiry := time.Until(srv.sharedCache.expires)
	srv.cacheMu.RUnlock()
	assert.Greater(t, fullExpiry, 30*time.Minute, "a clean discovery earns the full CacheTTL")

	linear.setListToolsErr(errTransientDiscovery)
	srv.cacheMu.Lock()
	srv.sharedCache = nil
	srv.cacheMu.Unlock()

	_, err = srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	srv.cacheMu.RLock()
	partialExpiry := time.Until(srv.sharedCache.expires)
	srv.cacheMu.RUnlock()
	assert.LessOrEqual(t, partialExpiry, partialDiscoveryCacheTTL,
		"a discovery that fell back to stale tools is not cached for the full TTL")
}

func TestStaleToolsExpireAfterStaleToolsTTL(t *testing.T) {
	linear := &mockTransport{tools: []mcp.Tool{{Name: "create_issue"}}}
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
		"linear":   linear,
	}
	srv := newStaleToolsTestServer(t, backends, &config.DiscoveryConfig{
		Timeout:  5 * time.Second,
		CacheTTL: 10 * time.Millisecond,
	})

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	linear.setListToolsErr(errTransientDiscovery)
	srv.cacheMu.Lock()
	srv.lastGood[lastGoodKey{backendName: "linear"}].discovered = time.Now().Add(-staleToolsTTL - time.Minute)
	srv.cacheMu.Unlock()
	time.Sleep(30 * time.Millisecond)

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 1)
	assert.Empty(t, tools["linear"], "tools older than the staleness bound are no longer served")
}

func TestBackendDiscoveryTimeout(t *testing.T) {
	srv := newStaleToolsTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	}, &config.DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: time.Minute})

	tests := []struct {
		name string
		conf *config.MCPClientConfig
		want time.Duration
	}{
		{"unset falls back to the discovery default", &config.MCPClientConfig{}, 10 * time.Second},
		{"shorter than the default does not shrink it", &config.MCPClientConfig{Timeout: 2 * time.Second}, 10 * time.Second},
		{"longer than the default is honoured", &config.MCPClientConfig{Timeout: 25 * time.Second}, 25 * time.Second},
		{"beyond the cap is clamped", &config.MCPClientConfig{Timeout: 5 * time.Minute}, maxBackendDiscoveryTimeout},
		{"nil config falls back to the default", nil, 10 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, srv.backendDiscoveryTimeout(tc.conf))
		})
	}
}

func TestCleanupPrunesRetainedDiscoveries(t *testing.T) {
	srv := newStaleToolsTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	}, &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: time.Minute})

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	srv.cacheMu.Lock()
	require.Len(t, srv.lastGood, 1)
	srv.lastGood[lastGoodKey{scope: "stale@test.com", backendName: "linear"}] = &backendTools{
		tools:      []mcp.Tool{{Name: "create_issue"}},
		discovered: time.Now().Add(-staleToolsTTL - time.Minute),
	}
	srv.cacheMu.Unlock()

	srv.cleanupExpiredCache()

	srv.cacheMu.RLock()
	defer srv.cacheMu.RUnlock()
	assert.Len(t, srv.lastGood, 1, "entries past the staleness bound are dropped")
	_, stillThere := srv.lastGood[lastGoodKey{backendName: "postgres"}]
	assert.True(t, stillThere, "a recent discovery is retained")
}

func TestBuiltinBackendCarriesUserEmail(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"gtm": {
			TransportType: config.MCPClientTypeBuiltin,
			Builtin:       "onboarding",
		},
	}

	var mu sync.Mutex
	var seenEmails []string
	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		mu.Lock()
		seenEmails = append(seenEmails, conf.UserEmail)
		mu.Unlock()
		return newMockTransport([]mcp.Tool{
			{Name: "create_onboarding_link", Description: "Generate a short onboarding URL"},
		}), nil
	}

	srv := NewServer(ServerConfig{
		Name:            "test-aggregate",
		Backends:        backendConfigs,
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		CreateTransport: factory,
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "ae@vori.com")
	require.NoError(t, err)
	require.Len(t, tools["gtm"], 1)
	assert.Equal(t, "create_onboarding_link", tools["gtm"][0].Name)

	handler := toolHandlerAs(srv, "ae@vori.com")
	req := mcp.CallToolRequest{}
	req.Params.Name = PrefixToolName("gtm", "create_onboarding_link", srv.delimiter)
	_, err = handler(context.Background(), req)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, seenEmails)
	for _, email := range seenEmails {
		assert.Equal(t, "ae@vori.com", email,
			"createConn must stamp the caller onto a builtin's config")
	}
}

func TestUserEmailHeaderAppliedToBackendConfig(t *testing.T) {
	newBackends := func() map[string]*config.MCPClientConfig {
		return map[string]*config.MCPClientConfig{
			"caura": {
				TransportType: config.MCPClientTypeStreamable,
				URL:           "http://localhost/caura",
				Headers: map[string]string{
					"X-Agent-ID":  "{{email}}",
					"X-Tenant-ID": "vori",
				},
				HeadersNeedEmail: map[string]bool{
					"X-Agent-ID":  true,
					"X-Tenant-ID": false,
				},
			},
			"plain": {
				TransportType: config.MCPClientTypeStreamable,
				URL:           "http://localhost/plain",
			},
		}
	}

	newServer := func(t *testing.T, backendConfigs map[string]*config.MCPClientConfig, seen map[string]map[string]string, mu *sync.Mutex) *Server {
		t.Helper()
		factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
			mu.Lock()
			headers := make(map[string]string, len(conf.Headers))
			maps.Copy(headers, conf.Headers)
			for name, bc := range backendConfigs {
				if conf.URL == bc.URL {
					seen[name] = headers
				}
			}
			mu.Unlock()
			return &mockTransport{tools: []mcp.Tool{{Name: "caura_recall"}}}, nil
		}

		srv := NewServer(ServerConfig{
			Name:            "test-aggregate",
			Backends:        backendConfigs,
			Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
			CreateTransport: factory,
		})
		srv.Start()
		t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
		return srv
	}

	t.Run("the caller's email reaches the upstream request", func(t *testing.T) {
		var mu sync.Mutex
		seen := make(map[string]map[string]string)
		backendConfigs := newBackends()
		srv := newServer(t, backendConfigs, seen, &mu)

		_, err := srv.getOrCreateConn(context.Background(), "ae@vori.com", "caura")
		require.NoError(t, err)
		_, err = srv.getOrCreateConn(context.Background(), "ae@vori.com", "plain")
		require.NoError(t, err)

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "ae@vori.com", seen["caura"]["X-Agent-ID"])
		assert.Equal(t, "vori", seen["caura"]["X-Tenant-ID"])
		assert.NotContains(t, seen["plain"], "X-Agent-ID")

		assert.Equal(t, "{{email}}", backendConfigs["caura"].Headers["X-Agent-ID"],
			"the shared backend config must not be mutated")
	})

	t.Run("a connection with no authenticated user is refused", func(t *testing.T) {
		var mu sync.Mutex
		seen := make(map[string]map[string]string)
		srv := newServer(t, newBackends(), seen, &mu)

		_, err := srv.getOrCreateConn(context.Background(), "anonymous", "caura")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no authenticated user")

		mu.Lock()
		defer mu.Unlock()
		assert.NotContains(t, seen, "caura", "no transport is opened without an identity")
	})
}

func toolCallLines(records []map[string]any) []map[string]any {
	var out []map[string]any
	for _, record := range records {
		if record["mcp.method.name"] == "tools/call" {
			out = append(out, record)
		}
	}
	return out
}

func TestToolCallRecordedOnTheRequestLogContext(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	})

	ctx, rc := reqlog.Inject(context.Background())
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.NoError(t, err)

	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.Equal(t, "query", tool.Name)
	assert.Equal(t, "postgres", tool.Backend)
	assert.False(t, tool.Failed)
}

func TestToolCallReportsAToolReportedFailure(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {
			tools: []mcp.Tool{{Name: "query"}},
			callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{IsError: true}, nil
			},
		},
	})

	ctx, rc := reqlog.Inject(context.Background())
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.NoError(t, err)

	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.True(t, tool.Failed)
}

func TestToolCallReportsATransportFailure(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {
			tools: []mcp.Tool{{Name: "query"}},
			callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, fmt.Errorf("connection refused")
			},
		},
	})

	ctx, rc := reqlog.Inject(context.Background())
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.Error(t, err)

	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.True(t, tool.Failed)
	assert.Equal(t, "query", tool.Name)
}

func TestRetriedToolCallIsReportedOnce(t *testing.T) {
	var calls int
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {
			tools: []mcp.Tool{{Name: "query"}},
			callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				calls++
				if calls == 1 {
					return nil, fmt.Errorf("Invalid session ID")
				}
				return &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent("ok")}}, nil
			},
		},
	})

	readLogs := testutil.CaptureLogs(t)
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "the session error should have been retried")
	assert.Len(t, toolCallLines(readLogs()), 1)
}

func TestToolCallIsLoggedWithoutARequestLogContext(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	})

	readLogs := testutil.CaptureLogs(t)
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.NoError(t, err)

	lines := toolCallLines(readLogs())
	require.Len(t, lines, 1)
	assert.Equal(t, "query", lines[0]["mcp.tool.name"])
	assert.Equal(t, "postgres", lines[0]["mcp.backend.name"])
	assert.Equal(t, "user@test.com", lines[0]["enduser.id"])
	assert.Equal(t, false, lines[0]["mcp.tool.is_error"])
	assert.Equal(t, true, lines[0]["succeeded"])
	assert.Equal(t, "INFO", lines[0]["level"])
	assert.Equal(t, true, lines[0]["is_canonical"])
	assert.Regexp(t, `^\[CANONICAL-REQUEST-LOG\] tools/call postgres.query succeeded in \d+ms$`, lines[0]["msg"])
}

func TestToolCallLogsTheSizeOfItsResult(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {
			tools: []mcp.Tool{{Name: "query"}},
			callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("3 rows"), nil
			},
		},
	})
	handler := toolHandlerAs(srv, "user@test.com")
	request := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"}}
	wantBytes := len(`{"content":[{"type":"text","text":"3 rows"}]}`)

	readLogs := testutil.CaptureLogs(t)
	_, err := handler(context.Background(), request)
	require.NoError(t, err)
	lines := toolCallLines(readLogs())
	require.Len(t, lines, 1)
	assert.Equal(t, float64(wantBytes), lines[0]["mcp.tool.result.size"])

	ctx, rc := reqlog.Inject(context.Background())
	_, err = handler(ctx, request)
	require.NoError(t, err)
	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.Equal(t, wantBytes, tool.ResultBytes)
}

func TestToolCallLineCarriesTheRequestBody(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	})

	readLogs := testutil.CaptureLogs(t)
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "postgres" + srv.delimiter + "query",
			Arguments: map[string]any{"sql": "select * from customers"},
		},
	})
	require.NoError(t, err)

	lines := toolCallLines(readLogs())
	require.Len(t, lines, 1)
	assert.JSONEq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"postgres.query","arguments":{"sql":"select * from customers"}}}`, lines[0]["request_body"].(string))
}

func TestFailedToolCallLineSaysWhy(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {
			tools: []mcp.Tool{{Name: "query"}},
			callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return nil, fmt.Errorf("connection refused")
			},
		},
	})

	readLogs := testutil.CaptureLogs(t)
	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.Error(t, err)

	lines := toolCallLines(readLogs())
	require.Len(t, lines, 1)
	assert.Equal(t, false, lines[0]["succeeded"])
	assert.Equal(t, "ERROR", lines[0]["level"])
	assert.Equal(t, "connection refused", lines[0]["error.message"])
	assert.Equal(t, float64(0), lines[0]["mcp.tool.result.size"])
	assert.Contains(t, lines[0]["msg"], "tools/call postgres.query failed in")
}

func TestToolCallCarriesTheSessionID(t *testing.T) {
	srv := newTestServer(t, map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	})

	session := fakeSession{id: "mcp-session-abc"}
	ctx, rc := reqlog.Inject(srv.mcpServer.WithContext(context.Background(), session))

	handler := toolHandlerAs(srv, "user@test.com")
	_, err := handler(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres" + srv.delimiter + "query"},
	})
	require.NoError(t, err)

	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.Equal(t, "mcp-session-abc", tool.SessionID)
}

func TestSupersededBackends(t *testing.T) {
	supersedes := map[string][]string{
		"notion": {"notion-read-only"},
		"sentry": {"sentry-read-only", "sentry-legacy"},
	}
	search := []mcp.Tool{{Name: "search"}}

	tests := []struct {
		name  string
		tools map[string][]mcp.Tool
		want  map[string]bool
	}{
		{
			name:  "a superseding backend with tools hides every backend it supersedes",
			tools: map[string][]mcp.Tool{"sentry": search, "sentry-read-only": search, "sentry-legacy": search, "notion-read-only": search},
			want:  map[string]bool{"sentry-read-only": true, "sentry-legacy": true},
		},
		{
			name:  "a superseding backend missing from discovery hides nothing",
			tools: map[string][]mcp.Tool{"notion-read-only": search, "sentry-read-only": search},
			want:  map[string]bool{},
		},
		{
			name:  "a superseding backend that contributed no tools hides nothing",
			tools: map[string][]mcp.Tool{"notion": {}, "notion-read-only": search},
			want:  map[string]bool{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, supersededBackends(supersedes, tt.tools))
		})
	}
}

type supersedeFixture struct {
	srv      *Server
	notion   *mockTransport
	readOnly *mockTransport
	hasToken atomic.Bool
}

func newSupersedeFixture(t *testing.T) *supersedeFixture {
	t.Helper()
	f := &supersedeFixture{
		notion:   newMockTransport([]mcp.Tool{{Name: "search"}, {Name: "update_page"}}),
		readOnly: newMockTransport([]mcp.Tool{{Name: "search"}}),
	}
	mocks := map[string]*mockTransport{
		"http://localhost/notion":           f.notion,
		"http://localhost/notion-read-only": f.readOnly,
		"http://localhost/linear":           newMockTransport([]mcp.Tool{{Name: "list_issues"}}),
	}
	f.srv = NewServer(ServerConfig{
		Name: "test-aggregate",
		Backends: map[string]*config.MCPClientConfig{
			"notion":           {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/notion", RequiresUserToken: true},
			"notion-read-only": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/notion-read-only"},
			"linear":           {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/linear"},
		},
		Discovery:  &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 20 * time.Millisecond},
		Delimiter:  "__",
		Supersedes: map[string][]string{"notion": {"notion-read-only"}},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			if userEmail != "alice@test.com" || !f.hasToken.Load() {
				return "", storage.ErrUserTokenNotFound
			}
			return "alice-notion-token", nil
		},
		CreateTransport: func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
			if mock, ok := mocks[conf.URL]; ok {
				return mock, nil
			}
			return nil, fmt.Errorf("unknown backend")
		},
	})
	f.srv.Start()
	t.Cleanup(func() { _ = f.srv.Shutdown(context.Background()) })
	return f
}

func (f *supersedeFixture) viewToolNames(t *testing.T, userEmail string) []string {
	t.Helper()
	f.srv.refreshView(context.Background(), userEmail)
	f.srv.cacheMu.RLock()
	defer f.srv.cacheMu.RUnlock()
	view := f.srv.views[userEmail]
	require.NotNil(t, view)
	return slices.Sorted(maps.Keys(view.tools))
}

func (f *supersedeFixture) afterCacheExpiry() {
	time.Sleep(50 * time.Millisecond)
}

func TestViewSwapsReadOnlyBackendForTheOneTheUserConnects(t *testing.T) {
	f := newSupersedeFixture(t)
	require.Equal(t, []string{"linear__list_issues", "notion-read-only__search"}, f.viewToolNames(t, "alice@test.com"), "without a token the user sees the read-only backend")

	f.hasToken.Store(true)
	f.afterCacheExpiry()

	assert.Equal(t, []string{"linear__list_issues", "notion__search", "notion__update_page"}, f.viewToolNames(t, "alice@test.com"))

	aliceCtx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "alice@test.com")
	_, err := f.srv.callTool(aliceCtx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "notion-read-only__search"}})
	assert.ErrorIs(t, err, mcpserver.ErrToolNotFound)
}

func TestSupersedesAppliesToEachUsersOwnConnections(t *testing.T) {
	f := newSupersedeFixture(t)
	f.hasToken.Store(true)

	assert.Equal(t, []string{"linear__list_issues", "notion__search", "notion__update_page"}, f.viewToolNames(t, "alice@test.com"))
	assert.Equal(t, []string{"linear__list_issues", "notion-read-only__search"}, f.viewToolNames(t, "bob@test.com"))

	bobCtx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "bob@test.com")
	_, err := f.srv.callTool(bobCtx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "notion-read-only__search"}})
	assert.NoError(t, err)
}

func TestReadOnlyBackendStaysWhenTheConnectedBackendFailsDiscovery(t *testing.T) {
	f := newSupersedeFixture(t)
	f.hasToken.Store(true)
	f.notion.setListToolsErr(transport.ErrAuthorizationRequired)

	assert.Equal(t, []string{"linear__list_issues", "notion-read-only__search"}, f.viewToolNames(t, "alice@test.com"))
}

func TestReadOnlyBackendStaysHiddenWhileTheConnectedBackendServesLastKnownTools(t *testing.T) {
	f := newSupersedeFixture(t)
	f.hasToken.Store(true)
	require.Equal(t, []string{"linear__list_issues", "notion__search", "notion__update_page"}, f.viewToolNames(t, "alice@test.com"))

	f.notion.setListToolsErr(errTransientDiscovery)
	f.afterCacheExpiry()

	assert.Equal(t, []string{"linear__list_issues", "notion__search", "notion__update_page"}, f.viewToolNames(t, "alice@test.com"))
}

func TestViewDropsReadOnlyToolsEvenWhenTheirOwnDiscoveryFails(t *testing.T) {
	f := newSupersedeFixture(t)
	require.Equal(t, []string{"linear__list_issues", "notion-read-only__search"}, f.viewToolNames(t, "alice@test.com"))

	f.hasToken.Store(true)
	f.readOnly.setListToolsErr(transport.ErrAuthorizationRequired)
	f.afterCacheExpiry()

	assert.Equal(t, []string{"linear__list_issues", "notion__search", "notion__update_page"}, f.viewToolNames(t, "alice@test.com"))
}

type fakeSession struct{ id string }

func (f fakeSession) Initialize()       {}
func (f fakeSession) Initialized() bool { return true }
func (f fakeSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return make(chan mcp.JSONRPCNotification, 1)
}
func (f fakeSession) SessionID() string { return f.id }

func TestRegisteredToolFollowsItsDefinition(t *testing.T) {
	pg := newMockTransport([]mcp.Tool{{Name: "query", Description: "old"}})
	srv := newStaleToolsTestServer(t, map[string]*mockTransport{"postgres": pg},
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 50 * time.Millisecond})
	ctx := context.Background()

	srv.refreshView(ctx, "alice@test.com")
	require.Equal(t, "old", srv.mcpServer.GetTool("postgres.query").Tool.Description)

	pg.mu.Lock()
	pg.tools = []mcp.Tool{{Name: "query", Description: "new"}}
	pg.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	srv.refreshView(ctx, "alice@test.com")

	assert.Equal(t, "new", srv.mcpServer.GetTool("postgres.query").Tool.Description)
}
