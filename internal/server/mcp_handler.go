package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/servicecontext"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// SessionManager defines the interface for managing stdio sessions
type SessionManager interface {
	GetSession(key client.SessionKey) (*client.StdioSession, bool)
	GetOrCreateSession(ctx context.Context, key client.SessionKey, config *config.MCPClientConfig, info mcp.Implementation, setupBaseURL string, userToken string) (*client.StdioSession, error)
	RemoveSession(key client.SessionKey) error
	Shutdown()
}

// UserTokenFunc defines a function that retrieves a formatted user token for a service
type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

// MCPHandler handles MCP requests with session management for stdio servers
type MCPHandler struct {
	serverName      string
	serverConfig    *config.MCPClientConfig
	storage         storage.Storage
	setupBaseURL    string
	info            mcp.Implementation
	sessionManager  SessionManager
	sharedSSEServer *server.SSEServer // Shared SSE server for stdio servers
	sharedMCPServer *server.MCPServer // Shared MCP server for stdio servers
	getUserToken    UserTokenFunc     // Function to get formatted user tokens
	sessionStore    *streamableSessionStore
	msgRelay        *messageRelay
}

// NewMCPHandler creates a new MCP handler with session management
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	storage storage.Storage,
	setupBaseURL string,
	info mcp.Implementation,
	sessionManager SessionManager,
	sharedSSEServer *server.SSEServer, // Shared SSE server for stdio servers
	sharedMCPServer *server.MCPServer, // Shared MCP server for stdio servers
	getUserToken UserTokenFunc,
) *MCPHandler {
	return &MCPHandler{
		serverName:      serverName,
		serverConfig:    serverConfig,
		storage:         storage,
		setupBaseURL:    setupBaseURL,
		info:            info,
		sessionManager:  sessionManager,
		sharedSSEServer: sharedSSEServer,
		sharedMCPServer: sharedMCPServer,
		getUserToken:    getUserToken,
		sessionStore:    newStreamableSessionStore(),
		msgRelay:        newMessageRelay(),
	}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context - could be OAuth email or basic auth username
	userEmail, _ := oauth.GetUserFromContext(ctx)
	if userEmail == "" {
		// Check for basic auth username
		username, _ := servicecontext.GetUser(ctx)
		userEmail = username
	}

	// Get user token if available for applying to config
	// Don't block connection if missing - will check at tool invocation
	var userToken string
	if h.serverConfig.RequiresUserToken && userEmail != "" {
		userToken, _ = h.getUserTokenIfAvailable(ctx, userEmail)
	}

	// Apply user token to config if available
	serverConfig := h.serverConfig
	if userToken != "" {
		serverConfig = serverConfig.ApplyUserToken(userToken)
	}

	if serverConfig.TransportType == config.MCPClientTypeStreamable {
		switch r.Method {
		case http.MethodPost:
			log.LogInfoWithFields("mcp", "Handling streamable POST request", map[string]any{
				"path":          r.URL.Path,
				"server":        h.serverName,
				"user":          userEmail,
				"remoteAddr":    r.RemoteAddr,
				"contentLength": r.ContentLength,
			})
			h.handleStreamablePost(ctx, w, r, userEmail, serverConfig)
		case http.MethodGet:
			log.LogInfoWithFields("mcp", "Handling streamable GET request", map[string]any{
				"path":       r.URL.Path,
				"server":     h.serverName,
				"user":       userEmail,
				"remoteAddr": r.RemoteAddr,
				"userAgent":  r.UserAgent(),
			})
			h.handleStreamableGet(ctx, w, r, userEmail, serverConfig)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	} else {
		if h.isMessageRequest(r) {
			log.LogInfoWithFields("mcp", "Handling message request", map[string]any{
				"path":          r.URL.Path,
				"server":        h.serverName,
				"isStdio":       serverConfig.IsStdio(),
				"user":          userEmail,
				"remoteAddr":    r.RemoteAddr,
				"contentLength": r.ContentLength,
				"query":         r.URL.RawQuery,
			})
			h.handleMessageRequest(ctx, w, r, userEmail, serverConfig)
		} else {
			log.LogInfoWithFields("mcp", "Handling SSE request", map[string]any{
				"path":       r.URL.Path,
				"server":     h.serverName,
				"isStdio":    serverConfig.IsStdio(),
				"user":       userEmail,
				"remoteAddr": r.RemoteAddr,
				"userAgent":  r.UserAgent(),
			})
			h.handleSSERequest(ctx, w, r, userEmail, serverConfig)
		}
	}
}

// isMessageRequest checks if this is a message endpoint request
func (h *MCPHandler) isMessageRequest(r *http.Request) bool {
	// Check if path ends with /message or contains /message?
	path := r.URL.Path
	return strings.HasSuffix(path, "/message") || strings.Contains(path, "/message?")
}

// handleSSERequest handles SSE connection requests for stdio servers
func (h *MCPHandler) handleSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	if !config.IsStdio() {
		// For non-stdio servers, handle normally
		h.handleNonStdioSSERequest(ctx, w, r, userEmail, config)
		return
	}

	// For stdio servers, use the shared SSE server
	if h.sharedSSEServer == nil {
		log.LogErrorWithFields("mcp", "No shared SSE server configured for stdio server", map[string]any{
			"server": h.serverName,
		})
		jsonwriter.WriteInternalServerError(w, "server misconfiguration")
		return
	}

	// The shared MCP server already has hooks configured in handler.go
	// that will be called when sessions are registered/unregistered
	// We need to set up our session-specific handlers
	// Create a custom hook handler for this specific request
	sessionHandler := NewSessionRequestHandler(h, userEmail, config, h.sharedMCPServer)

	// Store the handler in context so hooks can access it
	ctx = context.WithValue(ctx, SessionHandlerKey{}, sessionHandler)
	r = r.WithContext(ctx)
	log.LogInfoWithFields("mcp", "Serving SSE request for stdio server", map[string]any{
		"server": h.serverName,
		"user":   userEmail,
		"path":   r.URL.Path,
	})

	// Use the shared SSE server directly
	h.sharedSSEServer.ServeHTTP(w, r)
}

// handleMessageRequest handles message endpoint requests
func (h *MCPHandler) handleMessageRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	if config.IsStdio() {
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			jsonrpc.WriteError(w, nil, jsonrpc.InvalidParams, "missing sessionId")
			return
		}

		key := client.SessionKey{
			UserEmail:  userEmail,
			ServerName: h.serverName,
			SessionID:  sessionID,
		}

		log.LogDebugWithFields("mcp", "Looking up stdio session", map[string]any{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})

		_, ok := h.sessionManager.GetSession(key)
		if !ok {
			log.LogWarnWithFields("mcp", "Session not found - returning 404 with JSON-RPC error per MCP spec", map[string]any{
				"sessionID": sessionID,
				"server":    h.serverName,
				"user":      userEmail,
			})
			// Per MCP spec: return HTTP 404 Not Found when session is terminated or not found
			// The response body MAY comprise a JSON-RPC error response
			jsonrpc.WriteErrorWithStatus(w, nil, jsonrpc.InvalidParams, "session not found", http.StatusNotFound)
			return
		}
		if h.sharedSSEServer == nil {
			log.LogErrorWithFields("mcp", "No shared SSE server configured", map[string]any{
				"sessionID": sessionID,
			})
			jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "server misconfiguration")
			return
		}

		log.LogDebugWithFields("mcp", "Forwarding message request to shared SSE server", map[string]any{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})

		h.sharedSSEServer.ServeHTTP(w, r)
		return
	}

	h.forwardMessageToBackend(ctx, w, r, config)
}

// handleNonStdioSSERequest handles SSE requests for non-stdio (native SSE) servers
func (h *MCPHandler) handleNonStdioSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	log.LogInfoWithFields("mcp", "Proxying SSE request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	// Forward the SSE request directly to the backend
	forwardSSEToBackend(ctx, w, r, config)
}

// getUserTokenIfAvailable gets the user token if available, but doesn't send error responses
func (h *MCPHandler) getUserTokenIfAvailable(ctx context.Context, userEmail string) (string, error) {
	if userEmail == "" {
		return "", fmt.Errorf("authentication required")
	}

	log.LogTraceWithFields("mcp_handler", "Attempting to resolve user token", map[string]any{
		"server_name": h.serverName,
		"user":        userEmail,
	})

	// Check for service auth first - services provide their own user tokens
	if serviceAuth, ok := servicecontext.GetAuthInfo(ctx); ok {
		if serviceAuth.UserToken != "" {
			log.LogTraceWithFields("mcp_handler", "Found user token in service auth context", map[string]any{
				"server_name": h.serverName,
				"user":        userEmail,
			})
			return serviceAuth.UserToken, nil
		}
	}

	log.LogTraceWithFields("mcp_handler", "No user token in service auth context, falling back to storage lookup", map[string]any{
		"server_name": h.serverName,
		"user":        userEmail,
	})

	return h.getUserToken(ctx, userEmail, h.serverName, h.serverConfig)
}

func (h *MCPHandler) forwardMessageToBackend(ctx context.Context, w http.ResponseWriter, r *http.Request, config *config.MCPClientConfig) {
	backendURL := strings.TrimSuffix(config.URL, "/sse") + "/message"
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to read request body", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "failed to read request")
		return
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, backendURL, bytes.NewReader(body))
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to create backend request", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
			"url":    backendURL,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "failed to create request")
		return
	}

	// Copy relevant headers from original request, excluding hop-by-hop and sensitive headers
	copyRequestHeaders(req.Header, r.Header)

	// Ensure Content-Type is set
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add configured headers (e.g., auth headers)
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	log.LogDebugWithFields("mcp", "Forwarding message to backend", map[string]any{
		"server":     h.serverName,
		"backendURL": backendURL,
		"method":     r.Method,
		"headers":    config.Headers,
	})

	client := &http.Client{
		Timeout: config.Timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("mcp", "Backend request failed", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
			"url":    backendURL,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "backend request failed")
		return
	}
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)

	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.LogErrorWithFields("mcp", "Failed to copy response body", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
		})
	}
}

// handleStreamablePost handles POST requests for streamable-http transport.
// If an active SSE relay exists for the user (SSE transport mode), the backend response is
// forwarded via the relay channel and the client receives 202 Accepted. Otherwise the response
// is returned directly (streamable-http mode).
func (h *MCPHandler) handleStreamablePost(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	// Inject stored session ID if the client didn't include one.
	if r.Header.Get("Mcp-Session-Id") == "" && userEmail != "" {
		if id, ok := h.sessionStore.get(userEmail); ok {
			r = r.Clone(ctx)
			r.Header.Set("Mcp-Session-Id", id)
		}
	}

	log.LogInfoWithFields("mcp", "Proxying streamable POST request to backend", map[string]any{
		"service":    h.serverName,
		"user":       userEmail,
		"backend":    config.URL,
		"hasSession": r.Header.Get("Mcp-Session-Id") != "",
	})

	if userEmail != "" && h.msgRelay.hasSubscribers(userEmail) {
		h.handleStreamablePostWithRelay(ctx, w, r, userEmail, config)
		return
	}

	var onResponse func(http.Header)
	if userEmail != "" {
		onResponse = func(headers http.Header) {
			if sessionID := headers.Get("Mcp-Session-Id"); sessionID != "" {
				h.sessionStore.store(userEmail, sessionID)
			}
		}
	}

	forwardStreamablePostToBackend(ctx, w, r, config, onResponse)
}

// handleStreamablePostWithRelay forwards a POST to the backend, relays the response to the
// active SSE stream, and returns 202 Accepted to the MCP client.
func (h *MCPHandler) handleStreamablePostWithRelay(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to read request body", map[string]any{
			"service": h.serverName,
			"error":   err.Error(),
		})
		w.WriteHeader(http.StatusAccepted)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(body))
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	copyRequestHeaders(req.Header, r.Header)
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")

	client := &http.Client{Timeout: config.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("mcp", "Backend request failed in relay mode", map[string]any{
			"service": h.serverName,
			"error":   err.Error(),
		})
		errData, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"error":   map[string]any{"code": -32603, "message": "backend request failed"},
		})
		h.msgRelay.publish(userEmail, errData)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	defer resp.Body.Close()

	if sessionID := resp.Header.Get("Mcp-Session-Id"); sessionID != "" {
		h.sessionStore.store(userEmail, sessionID)
	}

	contentType := resp.Header.Get("Content-Type")
	log.LogInfoWithFields("mcp", "Backend response in relay mode", map[string]any{
		"service":     h.serverName,
		"user":        userEmail,
		"status":      resp.StatusCode,
		"contentType": contentType,
	})

	if strings.HasPrefix(contentType, "text/event-stream") {
		scanner := bufio.NewScanner(resp.Body)
		published := 0
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				payload := []byte(strings.TrimPrefix(line, "data: "))
				if len(payload) > 0 {
					h.msgRelay.publish(userEmail, payload)
					published++
				}
			}
		}
		log.LogInfoWithFields("mcp", "Relayed SSE events from backend", map[string]any{
			"service":   h.serverName,
			"user":      userEmail,
			"published": published,
		})
	} else {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if len(respBody) > 0 {
			published := h.msgRelay.publish(userEmail, respBody)
			log.LogInfoWithFields("mcp", "Relayed JSON response from backend", map[string]any{
				"service":   h.serverName,
				"user":      userEmail,
				"bytes":     len(respBody),
				"published": published,
			})
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

// handleStreamableGet handles GET requests for streamable-http transport.
// It acts as an SSE adapter: sends an endpoint event so SSE transport clients (like Claude Code)
// know where to POST, then relays POST responses back through this stream.
// The backend session is created lazily on the first POST; we do not pre-initialize here to
// avoid sending a duplicate initialize to the backend.
func (h *MCPHandler) handleStreamableGet(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	acceptHeader := r.Header.Get("Accept")
	if !strings.Contains(acceptHeader, "text/event-stream") {
		http.Error(w, "GET requests must accept text/event-stream", http.StatusNotAcceptable)
		return
	}

	var ch chan []byte
	var unsub func()
	if userEmail != "" {
		ch, unsub = h.msgRelay.subscribe(userEmail)
		defer unsub()
	}

	log.LogInfoWithFields("mcp", "Opening SSE adapter for streamable backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.LogError("Response writer doesn't support flushing")
		return
	}

	// Send endpoint event with the full message URL so SSE transport clients can POST.
	endpointURL := fmt.Sprintf("%s/%s/message", strings.TrimSuffix(h.setupBaseURL, "/"), h.serverName)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	if ch == nil {
		<-ctx.Done()
		return
	}

	for {
		select {
		case data := <-ch:
			log.LogInfoWithFields("mcp", "Relaying message to SSE client", map[string]any{
				"service": h.serverName,
				"user":    userEmail,
				"bytes":   len(data),
			})
			// Compact to a single line to keep SSE format valid.
			var compact bytes.Buffer
			if err := json.Compact(&compact, data); err == nil {
				data = compact.Bytes()
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// ensureBackendSession returns a stored session ID or creates one via POST initialize.
func (h *MCPHandler) ensureBackendSession(ctx context.Context, userEmail string, cfg *config.MCPClientConfig) string {
	if id, ok := h.sessionStore.get(userEmail); ok {
		return id
	}

	initBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    h.info.Name,
				"version": h.info.Version,
			},
		},
	})
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to marshal initialize request", map[string]any{
			"service": h.serverName,
			"error":   err.Error(),
		})
		return ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(initBody))
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to create initialize request", map[string]any{
			"service": h.serverName,
			"error":   err.Error(),
		})
		return ""
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("mcp", "Backend initialize request failed", map[string]any{
			"service": h.serverName,
			"error":   err.Error(),
		})
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		log.LogWarnWithFields("mcp", "Backend did not return Mcp-Session-Id", map[string]any{
			"service": h.serverName,
			"status":  resp.StatusCode,
		})
		return ""
	}

	h.sessionStore.store(userEmail, sessionID)
	log.LogInfoWithFields("mcp", "Backend session established", map[string]any{
		"service":   h.serverName,
		"user":      userEmail,
		"sessionID": sessionID,
	})
	return sessionID
}
