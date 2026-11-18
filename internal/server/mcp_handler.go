package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/jsonrpc"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
)

// UserTokenFunc defines a function that retrieves a formatted user token for a service
type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

// MCPHandler proxies MCP requests to a streamable-http backend
type MCPHandler struct {
	serverName   string
	serverConfig *config.MCPClientConfig
	getUserToken UserTokenFunc
}

func NewMCPHandler(serverName string, serverConfig *config.MCPClientConfig, getUserToken UserTokenFunc) *MCPHandler {
	return &MCPHandler{
		serverName:   serverName,
		serverConfig: serverConfig,
		getUserToken: getUserToken,
	}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userEmail, _ := oauth.GetUserFromContext(ctx)

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

	if serverConfig.NeedsUserEmail() {
		// A backend that trusts this header cannot tell a blank value apart
		// from a real identity, so refuse the request instead of sending one.
		if userEmail == "" {
			log.LogWarnWithFields("mcp", "Rejecting request for a backend that needs the caller's email", map[string]any{
				"server":     h.serverName,
				"path":       r.URL.Path,
				"remoteAddr": r.RemoteAddr,
			})
			jsonrpc.WriteErrorWithStatus(w, nil, jsonrpc.InvalidRequest, "authentication required", http.StatusUnauthorized)
			return
		}
		serverConfig = serverConfig.ApplyUserEmail(userEmail)
	}

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

// handleStreamablePost handles POST requests for streamable-http transport
func (h *MCPHandler) handleStreamablePost(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	log.LogInfoWithFields("mcp", "Proxying streamable POST request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	forwardStreamablePostToBackend(ctx, w, r, config)
}

// handleStreamableGet handles GET requests for streamable-http transport
func (h *MCPHandler) handleStreamableGet(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	acceptHeader := r.Header.Get("Accept")
	if !strings.Contains(acceptHeader, "text/event-stream") {
		http.Error(w, "GET requests must accept text/event-stream", http.StatusNotAcceptable)
		return
	}

	log.LogInfoWithFields("mcp", "Proxying streamable GET request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	forwardSSEToBackend(ctx, w, r, config)
}
