package aggregate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stainless-api/mcp-front/internal/client"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/storage"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	connIdleTimeout     = 5 * time.Minute
	connCleanupInterval = 1 * time.Minute

	// sessionIdleTTL bounds how long a streamable-http session's per-session
	// transport state (notably its per-session tool map) is retained after the
	// session's last request before mcp-go's sweeper reaps it. It comfortably
	// exceeds a live client's inter-request idle gap so active sessions are not
	// churned, while keeping retained sessions proportional to recent activity
	// rather than growing without bound.
	sessionIdleTTL = 10 * time.Minute

	// staleToolsTTL bounds how long a failed backend may be served from its last
	// successful discovery before it is dropped.
	staleToolsTTL = 15 * time.Minute

	// partialDiscoveryCacheTTL caches a discovery that lost a backend, kept short
	// so a transient stall is retried rather than standing for a full CacheTTL.
	partialDiscoveryCacheTTL = 5 * time.Second

	// maxBackendDiscoveryTimeout caps the per-backend discovery deadline however
	// long the backend configures its own timeout.
	maxBackendDiscoveryTimeout = 30 * time.Second
)

var ErrUserConnLimitExceeded = fmt.Errorf("user connection limit exceeded")

// UserTokenFunc retrieves a user's token for a specific backend service.
type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

// connKey identifies a per-user, per-backend connection.
type connKey struct {
	userEmail   string
	backendName string
}

func (k connKey) String() string { return k.userEmail + "\x00" + k.backendName }

// conn is a long-lived connection to one backend for one user.
type conn struct {
	client       client.MCPClientInterface
	cancel       context.CancelFunc
	lastAccessed atomic.Pointer[time.Time]
}

// cachedTools holds discovered tool schemas, valid until expires.
type cachedTools struct {
	tools   map[string][]mcp.Tool // backendName -> filtered tools
	expires time.Time
}

// backendTools is the most recent successful discovery for a single backend.
type backendTools struct {
	tools      []mcp.Tool
	discovered time.Time
}

// lastGoodKey scopes a retained discovery. Shared backends use an empty scope;
// token-gated backends are scoped per user so one user's tools are never served
// to another.
type lastGoodKey struct {
	scope       string
	backendName string
}

// mcpTransport is satisfied by both mcpserver.SSEServer and mcpserver.StreamableHTTPServer.
type mcpTransport interface {
	http.Handler
	Shutdown(context.Context) error
}

// Server aggregates multiple MCP backends into a single endpoint.
// Tools from backends are namespaced as "backend.toolName".
type Server struct {
	name                string
	backends            map[string]*config.MCPClientConfig
	sharedBackends      map[string]*config.MCPClientConfig
	userBackends        map[string]*config.MCPClientConfig
	discovery           *config.DiscoveryConfig
	delimiter           string
	streamlineResponses bool
	getUserToken        UserTokenFunc
	tokenSources        map[string]oauth2.TokenSource
	createTransport     client.TransportCreator
	baseURL             string

	cacheMu        sync.RWMutex
	sharedCache    *cachedTools            // tools from backends needing no user token
	userCache      map[string]*cachedTools // token-gated tools, keyed by userEmail
	lastGood       map[lastGoodKey]*backendTools
	discoveryGroup singleflight.Group

	connMu    sync.RWMutex
	conns     map[connKey]*conn
	closed    bool
	connGroup singleflight.Group

	mcpServer *mcpserver.MCPServer
	transport mcpTransport

	stopCleanup  chan struct{}
	shutdownOnce sync.Once
	wg           sync.WaitGroup
}

type ServerConfig struct {
	Name                string
	TransportType       config.MCPClientType
	Backends            map[string]*config.MCPClientConfig
	Discovery           *config.DiscoveryConfig
	Delimiter           string
	StreamlineResponses bool
	GetUserToken        UserTokenFunc
	TokenSources        map[string]oauth2.TokenSource
	CreateTransport     client.TransportCreator
	BaseURL             string
}

func NewServer(cfg ServerConfig) *Server {
	delimiter := cfg.Delimiter
	if delimiter == "" {
		delimiter = config.DefaultAggregateDelimiter
	}

	// Partition backends: those needing no user token have identical tools for
	// every user and are cached globally; token-gated backends are discovered
	// and cached per-user.
	sharedBackends := make(map[string]*config.MCPClientConfig)
	userBackends := make(map[string]*config.MCPClientConfig)
	for name, conf := range cfg.Backends {
		if conf.RequiresUserToken {
			userBackends[name] = conf
		} else {
			sharedBackends[name] = conf
		}
	}

	s := &Server{
		name:                cfg.Name,
		backends:            cfg.Backends,
		sharedBackends:      sharedBackends,
		userBackends:        userBackends,
		discovery:           cfg.Discovery,
		delimiter:           delimiter,
		streamlineResponses: cfg.StreamlineResponses,
		getUserToken:        cfg.GetUserToken,
		tokenSources:        cfg.TokenSources,
		createTransport:     cfg.CreateTransport,
		baseURL:             cfg.BaseURL,
		userCache:           make(map[string]*cachedTools),
		lastGood:            make(map[lastGoodKey]*backendTools),
		conns:               make(map[connKey]*conn),
		stopCleanup:         make(chan struct{}),
	}

	hooks := &mcpserver.Hooks{}
	hooks.AddOnRegisterSession(s.onRegisterSession)
	hooks.AddBeforeListTools(func(ctx context.Context, _ any, _ *mcp.ListToolsRequest) {
		s.populateToolsFromContext(ctx)
	})
	hooks.AddBeforeCallTool(func(ctx context.Context, _ any, _ *mcp.CallToolRequest) {
		s.populateToolsFromContext(ctx)
	})

	s.mcpServer = mcpserver.NewMCPServer(cfg.Name, "1.0.0",
		mcpserver.WithHooks(hooks),
		mcpserver.WithToolCapabilities(true),
	)

	switch cfg.TransportType {
	case config.MCPClientTypeStreamable:
		// StatelessGeneratingSessionIdManager mints fresh UUIDs for
		// `initialize` requests and validates subsequent IDs by format
		// only. A stale ID surviving a pod restart passes validation
		// instead of 400-ing, and the before-tool hooks above rebuild
		// the per-session tool list lazily for those rehydrated sessions.
		streamable := mcpserver.NewStreamableHTTPServer(s.mcpServer,
			mcpserver.WithEndpointPath("/"+cfg.Name+"/"),
			mcpserver.WithSessionIdManager(&mcpserver.StatelessGeneratingSessionIdManager{}),
			// Reap idle sessions' per-session state. Clients mint a fresh session
			// on every `initialize` and rarely send DELETE, so without a TTL the
			// per-session tool maps accumulate without bound and the process
			// leaks memory to its limit. Swept sessions are rebuilt lazily from
			// cached discovery on their next request (see the before-tool hooks
			// above), so reaping idle ones is safe.
			mcpserver.WithSessionIdleTTL(sessionIdleTTL),
		)
		s.transport = streamable
	default:
		sse := mcpserver.NewSSEServer(s.mcpServer,
			mcpserver.WithStaticBasePath(cfg.Name),
			mcpserver.WithBaseURL(cfg.BaseURL),
		)
		s.transport = sse
	}

	return s
}

func (s *Server) Start() {
	s.wg.Add(1)
	go s.cleanupLoop()
}

func (s *Server) Handler() http.Handler {
	return s.transport
}

// Name returns the aggregate server's name (used as a URL path prefix).
func (s *Server) Name() string {
	return s.name
}

// Backends returns the map of backend service configs.
func (s *Server) Backends() map[string]*config.MCPClientConfig {
	return s.backends
}

// ListToolsByBackend discovers and returns tools grouped by backend name.
// This is used for displaying tools on the /tools page.
func (s *Server) ListToolsByBackend(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	return s.getTools(ctx, userEmail)
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.shutdownOnce.Do(func() {
		close(s.stopCleanup)
		s.wg.Wait()

		err = s.transport.Shutdown(ctx)

		s.connMu.Lock()
		s.closed = true
		snapshot := make(map[connKey]*conn, len(s.conns))
		maps.Copy(snapshot, s.conns)
		clear(s.conns)
		s.connMu.Unlock()

		for key, c := range snapshot {
			c.cancel()
			if closeErr := c.client.Close(); closeErr != nil {
				log.LogWarnWithFields("aggregate", "Error closing backend connection", map[string]any{
					"server":  s.name,
					"backend": key.backendName,
					"user":    key.userEmail,
					"error":   closeErr.Error(),
				})
			}
		}
	})
	return err
}

func (s *Server) onRegisterSession(ctx context.Context, session mcpserver.ClientSession) {
	s.ensureSessionTools(ctx, session)
}

// ensureSessionTools populates per-session tools if they are missing. It is
// called from OnRegisterSession (when a client runs `initialize`) and from
// the tools/list and tools/call before-hooks so that ephemeral sessions
// created for requests carrying a stale session ID (e.g. after a pod restart)
// transparently get their tool list rebuilt from the aggregate's cached
// discovery instead of appearing empty.
func (s *Server) ensureSessionTools(ctx context.Context, session mcpserver.ClientSession) {
	sessionWithTools, ok := session.(mcpserver.SessionWithTools)
	if !ok {
		log.LogErrorWithFields("aggregate", "Session does not support per-session tools", map[string]any{
			"server":    s.name,
			"sessionID": session.SessionID(),
		})
		return
	}
	if len(sessionWithTools.GetSessionTools()) > 0 {
		return
	}

	userEmail, _ := oauth.GetUserFromContext(ctx)
	if userEmail == "" {
		userEmail = "anonymous"
		log.LogInfoWithFields("aggregate", "No user identity in session context, using anonymous", map[string]any{
			"server":    s.name,
			"sessionID": session.SessionID(),
		})
	}

	tools, err := s.getTools(ctx, userEmail)
	if err != nil {
		log.LogErrorWithFields("aggregate", "Tool discovery failed", map[string]any{
			"server": s.name,
			"user":   userEmail,
			"error":  err.Error(),
		})
		return
	}

	sessionTools := make(map[string]mcpserver.ServerTool)
	for backendName, backendTools := range tools {
		for _, tool := range backendTools {
			namespacedName := PrefixToolName(backendName, tool.Name, s.delimiter)
			tool.Name = namespacedName
			if s.streamlineResponses {
				tool.Description = streamlineDescription(tool.Description)
				if len(tool.RawInputSchema) > 0 {
					tool.RawInputSchema = streamlineInputSchema(tool.RawInputSchema)
				}
			}
			sessionTools[namespacedName] = mcpserver.ServerTool{
				Tool:    tool,
				Handler: s.makeToolHandler(userEmail, backendName),
			}
		}
	}
	sessionWithTools.SetSessionTools(sessionTools)

	log.LogInfoWithFields("aggregate", "Session registered", map[string]any{
		"server":    s.name,
		"sessionID": session.SessionID(),
		"user":      userEmail,
		"toolCount": len(sessionTools),
	})
}

func (s *Server) populateToolsFromContext(ctx context.Context) {
	if session := mcpserver.ClientSessionFromContext(ctx); session != nil {
		s.ensureSessionTools(ctx, session)
	}
}

// discoveryCacheTTL returns how long a discovery result deserves to be cached.
func (s *Server) discoveryCacheTTL(complete bool) time.Duration {
	if complete {
		return s.discovery.CacheTTL
	}
	return min(s.discovery.CacheTTL, partialDiscoveryCacheTTL)
}

// getTools returns the tool set for a user: globally-shared backends plus the
// user's token-gated backends, merged. Shared backends are discovered once and
// cached for everyone; token-gated backends are discovered and cached per-user.
func (s *Server) getTools(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	shared, err := s.getSharedTools(ctx, userEmail)
	if err != nil {
		return nil, err
	}
	user, err := s.getUserTools(ctx, userEmail)
	if err != nil {
		return nil, err
	}

	// Shared and token-gated backend names are disjoint, so the union is
	// collision-free.
	merged := make(map[string][]mcp.Tool, len(shared)+len(user))
	maps.Copy(merged, shared)
	maps.Copy(merged, user)
	return merged, nil
}

// getSharedTools returns tools for backends that need no user token. Their
// schemas are identical for every user, so the result is cached globally.
// userEmail is used only to open connections during discovery (connections are
// pooled per-user); a run where every shared backend fails is an error, since
// it means shared infrastructure is down.
func (s *Server) getSharedTools(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	s.cacheMu.RLock()
	if s.sharedCache != nil && time.Now().Before(s.sharedCache.expires) {
		tools := s.sharedCache.tools
		s.cacheMu.RUnlock()
		return tools, nil
	}
	s.cacheMu.RUnlock()

	v, err, _ := s.discoveryGroup.Do("discover:shared", func() (any, error) {
		// Double-check inside singleflight.
		s.cacheMu.RLock()
		if s.sharedCache != nil && time.Now().Before(s.sharedCache.expires) {
			tools := s.sharedCache.tools
			s.cacheMu.RUnlock()
			return tools, nil
		}
		s.cacheMu.RUnlock()

		// Detach from the caller's context: singleflight shares this result
		// with all concurrent callers. If the first caller's context is
		// cancelled (e.g., SSE disconnect), discovery would fail for everyone.
		// discoverBackends applies its own timeout from DiscoveryConfig.
		discoveryCtx := context.WithoutCancel(ctx)
		tools, complete, err := s.discoverBackends(discoveryCtx, userEmail, "", s.sharedBackends, true)
		if err != nil {
			return nil, err
		}

		s.cacheMu.Lock()
		s.sharedCache = &cachedTools{
			tools:   tools,
			expires: time.Now().Add(s.discoveryCacheTTL(complete)),
		}
		s.cacheMu.Unlock()
		return tools, nil
	})

	if err != nil {
		return nil, err
	}
	return v.(map[string][]mcp.Tool), nil
}

// getUserTools returns tools for the token-gated backends the user has a token
// for. The result is cached per-user. A user with no configured tokens gets an
// empty set — that is expected, not an error.
func (s *Server) getUserTools(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	if len(s.userBackends) == 0 {
		return map[string][]mcp.Tool{}, nil
	}

	s.cacheMu.RLock()
	if cached, ok := s.userCache[userEmail]; ok && time.Now().Before(cached.expires) {
		tools := cached.tools
		s.cacheMu.RUnlock()
		return tools, nil
	}
	s.cacheMu.RUnlock()

	v, err, _ := s.discoveryGroup.Do("discover:user:"+userEmail, func() (any, error) {
		// Double-check inside singleflight.
		s.cacheMu.RLock()
		if cached, ok := s.userCache[userEmail]; ok && time.Now().Before(cached.expires) {
			tools := cached.tools
			s.cacheMu.RUnlock()
			return tools, nil
		}
		s.cacheMu.RUnlock()

		discoveryCtx := context.WithoutCancel(ctx)
		// Discover only the backends the user has a token for, so discovery
		// does not attempt — and log warnings for — doomed connections.
		backends := s.backendsWithUserToken(discoveryCtx, userEmail)
		tools, complete, err := s.discoverBackends(discoveryCtx, userEmail, userEmail, backends, false)
		if err != nil {
			return nil, err
		}

		s.cacheMu.Lock()
		s.userCache[userEmail] = &cachedTools{
			tools:   tools,
			expires: time.Now().Add(s.discoveryCacheTTL(complete)),
		}
		s.cacheMu.Unlock()
		return tools, nil
	})

	if err != nil {
		return nil, err
	}
	return v.(map[string][]mcp.Tool), nil
}

// backendsWithUserToken returns the subset of token-gated backends for which
// the user currently has a token. Backends without one are omitted so they are
// not discovered (and do not surface tools the user could not call anyway).
func (s *Server) backendsWithUserToken(ctx context.Context, userEmail string) map[string]*config.MCPClientConfig {
	available := make(map[string]*config.MCPClientConfig)
	if userEmail == "" || s.getUserToken == nil {
		return available
	}

	for name, conf := range s.userBackends {
		token, err := s.getUserToken(ctx, userEmail, name, conf)
		if err != nil {
			// Not connecting a backend is the expected steady state, not a fault.
			if errors.Is(err, storage.ErrUserTokenNotFound) {
				log.LogDebugWithFields("aggregate", "Backend not connected by user", map[string]any{
					"server":  s.name,
					"backend": name,
					"user":    userEmail,
				})
				continue
			}
			log.LogWarnWithFields("aggregate", "Failed to check user token", map[string]any{
				"server":  s.name,
				"backend": name,
				"user":    userEmail,
				"error":   err.Error(),
			})
			continue
		}
		if token != "" {
			available[name] = conf
		}
	}
	return available
}

// backendDiscoveryTimeout returns how long a single backend gets to initialize
// and list its tools, honouring a longer per-backend timeout up to the cap.
func (s *Server) backendDiscoveryTimeout(conf *config.MCPClientConfig) time.Duration {
	d := s.discovery.Timeout
	if conf != nil && conf.Timeout > d {
		d = conf.Timeout
	}
	return min(d, maxBackendDiscoveryTimeout)
}

func (s *Server) lastGoodTools(scope, backendName string) ([]mcp.Tool, bool) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	prev, ok := s.lastGood[lastGoodKey{scope: scope, backendName: backendName}]
	if !ok || time.Since(prev.discovered) > staleToolsTTL {
		return nil, false
	}
	return prev.tools, true
}

func (s *Server) storeLastGoodTools(scope, backendName string, tools []mcp.Tool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.lastGood[lastGoodKey{scope: scope, backendName: backendName}] = &backendTools{
		tools:      tools,
		discovered: time.Now(),
	}
}

// discoverBackends fans out tool discovery across the given backends in
// parallel, each under its own deadline. When errorIfAllFail is set, a run where
// every backend fails returns an error; otherwise the partial (possibly empty)
// result is returned. The bool reports whether every backend was discovered
// freshly, which callers use to pick a cache lifetime.
//
// A backend failing transiently falls back to its last successful discovery:
// clients snapshot the tool list when they connect, so dropping a backend for
// one slow moment hides it for their whole session. An auth failure is not
// transient, so those backends are still dropped.
func (s *Server) discoverBackends(ctx context.Context, userEmail, scope string, backends map[string]*config.MCPClientConfig, errorIfAllFail bool) (map[string][]mcp.Tool, bool, error) {
	if len(backends) == 0 {
		return map[string][]mcp.Tool{}, true, nil
	}

	fanOutTimeout := s.discovery.Timeout
	for _, conf := range backends {
		fanOutTimeout = max(fanOutTimeout, s.backendDiscoveryTimeout(conf))
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, fanOutTimeout)
	defer cancel()

	type result struct {
		backendName string
		tools       []mcp.Tool
		err         error
	}

	ch := make(chan result, len(backends))

	for name, conf := range backends {
		go func(name string, conf *config.MCPClientConfig) {
			backendCtx, backendCancel := context.WithTimeout(discoveryCtx, s.backendDiscoveryTimeout(conf))
			defer backendCancel()
			tools, err := s.discoverBackendTools(backendCtx, userEmail, name, conf)
			ch <- result{backendName: name, tools: tools, err: err}
		}(name, conf)
	}

	allTools := make(map[string][]mcp.Tool, len(backends))
	var errors []string
	stale := 0

	for range backends {
		r := <-ch
		if r.err != nil {
			log.LogWarnWithFields("aggregate", "Backend discovery failed", map[string]any{
				"server":  s.name,
				"backend": r.backendName,
				"error":   r.err.Error(),
			})
			if !isAuthError(r.err) {
				if tools, ok := s.lastGoodTools(scope, r.backendName); ok {
					allTools[r.backendName] = tools
					stale++
					log.LogInfoWithFields("aggregate", "Serving last known tools for backend", map[string]any{
						"server":  s.name,
						"backend": r.backendName,
						"user":    userEmail,
					})
					continue
				}
			}
			errors = append(errors, fmt.Sprintf("%s: %v", r.backendName, r.err))
			continue
		}
		allTools[r.backendName] = r.tools
		s.storeLastGoodTools(scope, r.backendName, r.tools)
	}

	totalTools := 0
	for _, tools := range allTools {
		totalTools += len(tools)
	}

	if errorIfAllFail && totalTools == 0 && len(errors) > 0 {
		return nil, false, fmt.Errorf("all backends failed discovery: %s", strings.Join(errors, "; "))
	}

	log.LogInfoWithFields("aggregate", "Tool discovery completed", map[string]any{
		"server":    s.name,
		"toolCount": totalTools,
		"errors":    len(errors),
		"stale":     stale,
	})

	return allTools, len(errors) == 0 && stale == 0, nil
}

// discoverBackendTools connects to a backend, lists its tools, and applies filtering.
func (s *Server) discoverBackendTools(ctx context.Context, userEmail, backendName string, conf *config.MCPClientConfig) ([]mcp.Tool, error) {
	var tools []mcp.Tool
	err := s.withConnRetry(ctx, userEmail, backendName, func(ctx context.Context, c *conn) error {
		// Reset so a retry against a fresh connection does not accumulate onto
		// tools collected during the failed first attempt.
		tools = nil
		req := mcp.ListToolsRequest{}
		for {
			resp, err := c.client.ListTools(ctx, req)
			if err != nil {
				return fmt.Errorf("listing tools: %w", err)
			}
			tools = append(tools, resp.Tools...)
			if resp.NextCursor == "" {
				break
			}
			req.Params.Cursor = resp.NextCursor
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	filter := toolFilterFunc(conf)
	filtered := make([]mcp.Tool, 0, len(tools))
	for _, tool := range tools {
		if filter(tool.Name) {
			filtered = append(filtered, tool)
		}
	}

	return filtered, nil
}

func (s *Server) makeToolHandler(userEmail, backendName string) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, originalName, ok := ParseToolName(request.Params.Name, s.delimiter)
		if !ok {
			return nil, fmt.Errorf("invalid namespaced tool name: %s", request.Params.Name)
		}
		request.Params.Name = originalName

		var result *mcp.CallToolResult
		err := s.withConnRetry(ctx, userEmail, backendName, func(ctx context.Context, c *conn) error {
			var callErr error
			result, callErr = c.client.CallTool(ctx, request)
			return callErr
		})
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", backendName, err)
		}
		return result, nil
	}
}

// withConnRetry runs fn against the pooled connection for (userEmail, backendName).
//
// A backend reached over streamable-http issues an Mcp-Session-Id at Initialize
// that the pooled connection reuses on every call. When the backend expires that
// session server-side before we evict the idle connection, the next call is
// rejected (e.g. Datadog returns "Invalid session ID"). mcp-go surfaces this as
// an error and does not re-initialize on its own — it expects the caller to.
//
// So on any error fn is evicted (the connection is unusable either way), and if
// the error looks like session invalidation, fn is retried once against a
// freshly-initialized connection, which mints a new session. This keeps the
// failure invisible to the client instead of proxying it through. A non-session
// error is returned after the single eviction, matching the previous behavior.
func (s *Server) withConnRetry(ctx context.Context, userEmail, backendName string, fn func(context.Context, *conn) error) error {
	key := connKey{userEmail: userEmail, backendName: backendName}

	c, err := s.getOrCreateConn(ctx, userEmail, backendName)
	if err != nil {
		return err
	}
	now := time.Now()
	c.lastAccessed.Store(&now)

	err = fn(ctx, c)
	if err == nil {
		return nil
	}

	// MCP-level tool errors are returned in the result with IsError set, not via
	// the error return, so an error here is a transport/protocol failure: the
	// connection is broken or its session was rejected. Evict it either way.
	s.evictConn(key, c)

	// A stale session or an expired bearer (client-credentials/user tokens are
	// captured into the pooled connection at createConn and never refreshed in
	// place) both heal the same way: recreate the connection, which mints a fresh
	// token, and retry once. Auth errors only retry when the backend has a
	// re-mintable credential, so a genuinely misconfigured backend is not retried.
	retryable := isSessionError(err) ||
		(isAuthError(err) && s.hasRefreshableCredential(backendName))
	if !retryable {
		return err
	}

	log.LogWarnWithFields("aggregate", "Backend connection rejected; retrying with a fresh connection", map[string]any{
		"server":  s.name,
		"backend": backendName,
		"user":    userEmail,
		"error":   err.Error(),
	})

	c, err = s.getOrCreateConn(ctx, userEmail, backendName)
	if err != nil {
		return err
	}
	now = time.Now()
	c.lastAccessed.Store(&now)

	if err := fn(ctx, c); err != nil {
		s.evictConn(key, c)
		log.LogErrorWithFields("aggregate", "Backend call failed after fresh-connection retry", map[string]any{
			"server":  s.name,
			"backend": backendName,
			"user":    userEmail,
			"error":   err.Error(),
		})
		return err
	}
	return nil
}

// isSessionError reports whether err indicates the backend no longer recognizes
// the session id held by the pooled connection. mcp-go returns
// transport.ErrSessionTerminated for an HTTP 404, but a backend may instead
// reject a stale session with another 4xx whose body carries the reason (e.g.
// Datadog's "Invalid session ID"), so the textual check covers that case too.
func isSessionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, transport.ErrSessionTerminated) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "session")
}

// isAuthError reports whether err is the backend rejecting the request's bearer
// (HTTP 401). mcp-go returns transport.AuthorizationRequiredError (unwrapping to
// ErrAuthorizationRequired) for the request path and ErrUnauthorized for the SSE
// listen path; both indicate the captured token is no longer accepted.
func isAuthError(err error) bool {
	return errors.Is(err, transport.ErrAuthorizationRequired) ||
		errors.Is(err, transport.ErrUnauthorized)
}

// hasRefreshableCredential reports whether recreating the backend's connection
// would mint a fresh credential: a client-credentials token source, or a user
// token re-fetched per connection. Without one, retrying a 401 would just reuse
// the same rejected bearer.
func (s *Server) hasRefreshableCredential(backendName string) bool {
	if _, ok := s.tokenSources[backendName]; ok {
		return true
	}
	cfg := s.backends[backendName]
	return cfg != nil && cfg.RequiresUserToken
}

func (s *Server) getOrCreateConn(ctx context.Context, userEmail, backendName string) (*conn, error) {
	key := connKey{userEmail: userEmail, backendName: backendName}

	v, err, _ := s.connGroup.Do(key.String(), func() (any, error) {
		s.connMu.RLock()
		existing, ok := s.conns[key]
		s.connMu.RUnlock()

		if ok {
			now := time.Now()
			existing.lastAccessed.Store(&now)
			return existing, nil
		}

		// Detach from the caller's context: singleflight shares this result
		// with concurrent callers for the same user+backend. createConn
		// applies its own timeout for the Initialize exchange.
		connCtx := context.WithoutCancel(ctx)
		return s.createConn(connCtx, userEmail, backendName)
	})

	if err != nil {
		return nil, err
	}
	return v.(*conn), nil
}

// evictConn removes a broken connection from the pool if it's still the current
// one for that key. The identity check (current == broken) prevents evicting a
// replacement that was created after the error occurred. Concurrent callers
// using the same broken connection will get transport errors and retry, which
// is correct since the connection is already broken.
func (s *Server) evictConn(key connKey, broken *conn) {
	s.connMu.Lock()
	current, ok := s.conns[key]
	if ok && current == broken {
		delete(s.conns, key)
	} else {
		ok = false
	}
	s.connMu.Unlock()

	if ok {
		broken.cancel()
		broken.client.Close()
		log.LogInfoWithFields("aggregate", "Evicted broken backend connection", map[string]any{
			"server":  s.name,
			"backend": key.backendName,
			"user":    key.userEmail,
		})
	}
}

func (s *Server) checkUserConnLimit(userEmail string) error {
	limit := s.discovery.MaxConnsPerUser
	if limit == 0 || userEmail == "anonymous" {
		return nil
	}

	s.connMu.RLock()
	count := 0
	for key := range s.conns {
		if key.userEmail == userEmail {
			count++
		}
	}
	s.connMu.RUnlock()

	if count >= limit {
		return fmt.Errorf("%w: user %s has %d connections (limit: %d)",
			ErrUserConnLimitExceeded, userEmail, count, limit)
	}
	return nil
}

func (s *Server) createConn(ctx context.Context, userEmail, backendName string) (*conn, error) {
	if err := s.checkUserConnLimit(userEmail); err != nil {
		return nil, err
	}

	backendConfig := s.backends[backendName]

	effectiveConfig := backendConfig
	if backendConfig.RequiresUserToken && userEmail != "" && s.getUserToken != nil {
		token, err := s.getUserToken(ctx, userEmail, backendName, backendConfig)
		if err != nil {
			log.LogWarnWithFields("aggregate", "Failed to get user token", map[string]any{
				"server":  s.name,
				"backend": backendName,
				"user":    userEmail,
				"error":   err.Error(),
			})
		} else if token != "" {
			effectiveConfig = backendConfig.ApplyUserToken(token)
		}
	}

	if ts, ok := s.tokenSources[backendName]; ok {
		token, err := ts.Token()
		if err != nil {
			return nil, fmt.Errorf("fetching token for %s: %w", backendName, err)
		}
		effectiveConfig = effectiveConfig.WithBearerToken(token.AccessToken)
	}

	transport, err := s.createTransport(effectiveConfig)
	if err != nil {
		return nil, fmt.Errorf("creating transport: %w", err)
	}

	connCtx, cancel := context.WithCancel(context.Background())

	if err := transport.Start(connCtx); err != nil {
		cancel()
		transport.Close()
		return nil, fmt.Errorf("starting: %w", err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: s.name, Version: "1.0.0"}
	// Initialize is a request-response exchange with its own timeout.
	// The caller's context is detached (via WithoutCancel in singleflight)
	// so we apply the backend's discovery timeout as an upper bound.
	// Start uses connCtx (background) because for SSE it controls the
	// persistent stream lifetime.
	initCtx, initCancel := context.WithTimeout(ctx, s.backendDiscoveryTimeout(backendConfig))
	defer initCancel()
	if _, err := transport.Initialize(initCtx, initReq); err != nil {
		cancel()
		transport.Close()
		return nil, fmt.Errorf("initializing: %w", err)
	}

	now := time.Now()
	c := &conn{
		client: transport,
		cancel: cancel,
	}
	c.lastAccessed.Store(&now)

	key := connKey{userEmail: userEmail, backendName: backendName}
	s.connMu.Lock()
	if s.closed {
		s.connMu.Unlock()
		cancel()
		transport.Close()
		return nil, fmt.Errorf("server is shut down")
	}
	s.conns[key] = c
	s.connMu.Unlock()

	log.LogInfoWithFields("aggregate", "Backend connection established", map[string]any{
		"server":  s.name,
		"backend": backendName,
		"user":    userEmail,
	})

	return c, nil
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(connCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanupIdleConns()
			s.cleanupExpiredCache()
		}
	}
}

func (s *Server) cleanupIdleConns() {
	now := time.Now()

	s.connMu.Lock()
	var toClose []*conn
	var toLog []connKey
	for key, c := range s.conns {
		last := c.lastAccessed.Load()
		if last != nil && now.Sub(*last) > connIdleTimeout {
			toClose = append(toClose, c)
			toLog = append(toLog, key)
			delete(s.conns, key)
		}
	}
	s.connMu.Unlock()

	for i, c := range toClose {
		log.LogInfoWithFields("aggregate", "Closing idle connection", map[string]any{
			"server":  s.name,
			"backend": toLog[i].backendName,
			"user":    toLog[i].userEmail,
		})
		c.cancel()
		c.client.Close()
	}
}

// cleanupExpiredCache drops expired per-user tool caches and retained
// discoveries so neither map grows unbounded as users come and go. The shared
// cache is a single entry and is simply overwritten on the next discovery, so
// it needs no pruning.
func (s *Server) cleanupExpiredCache() {
	now := time.Now()

	s.cacheMu.Lock()
	for user, cached := range s.userCache {
		if now.After(cached.expires) {
			delete(s.userCache, user)
		}
	}
	for key, prev := range s.lastGood {
		if now.Sub(prev.discovered) > staleToolsTTL {
			delete(s.lastGood, key)
		}
	}
	s.cacheMu.Unlock()
}

// toolFilterFunc builds a filter predicate from a backend's config.
func toolFilterFunc(conf *config.MCPClientConfig) func(string) bool {
	if conf.Options == nil || conf.Options.ToolFilter == nil || len(conf.Options.ToolFilter.List) == 0 {
		return func(string) bool { return true }
	}

	filter := conf.Options.ToolFilter
	set := make(map[string]struct{}, len(filter.List))
	for _, name := range filter.List {
		set[name] = struct{}{}
	}

	switch config.ToolFilterMode(strings.ToLower(string(filter.Mode))) {
	case config.ToolFilterModeAllow:
		return func(name string) bool {
			_, ok := set[name]
			return ok
		}
	case config.ToolFilterModeBlock:
		return func(name string) bool {
			_, ok := set[name]
			return !ok
		}
	default:
		panic(fmt.Sprintf("aggregate: invalid tool filter mode %q (should have been caught by config validation)", filter.Mode))
	}
}
