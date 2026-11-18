package inline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/jsonrpc"
	"github.com/stainless-api/mcp-front/internal/log"
)

// MCPServer defines the interface that Handler depends on
type MCPServer interface {
	GetCapabilities() ServerCapabilities
	HandleToolCall(ctx context.Context, toolName string, args map[string]any) (any, error)
	GetDescription() string
}

// Handler implements the MCP protocol for inline servers
type Handler struct {
	server MCPServer
	name   string
}

// NewHandler creates a new inline MCP handler
func NewHandler(name string, server MCPServer) *Handler {
	return &Handler{
		server: server,
		name:   name,
	}
}

// ServeHTTP answers streamable-http POSTs with a JSON response. Inline servers
// are stateless, so there is no session and no GET stream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	var request jsonrpc.Request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		jsonrpc.WriteInvalidJSON(w)
		return
	}

	if request.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch request.Method {
	case "initialize":
		h.handleInitialize(w, &request)
	case "tools/list":
		h.handleToolsList(w, &request)
	case "tools/call":
		h.handleToolCall(r.Context(), w, &request)
	default:
		jsonrpc.WriteError(w, request.ID, jsonrpc.MethodNotFound, "Method not found")
	}
}

// handleInitialize handles the initialize request
func (h *Handler) handleInitialize(w http.ResponseWriter, req *jsonrpc.Request) {
	result := map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    h.server.GetCapabilities(),
		"serverInfo": map[string]any{
			"name":    h.name,
			"version": "1.0",
		},
	}

	if err := jsonrpc.WriteResult(w, req.ID, result); err != nil {
		log.LogError("Failed to write initialize response: %v", err)
	}
}

// handleToolsList handles the tools/list request
func (h *Handler) handleToolsList(w http.ResponseWriter, req *jsonrpc.Request) {
	capabilities := h.server.GetCapabilities()

	tools := make([]map[string]any, 0, len(capabilities.Tools))
	for _, tool := range capabilities.Tools {
		tools = append(tools, map[string]any{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.InputSchema,
		})
	}

	result := map[string]any{
		"tools": tools,
	}

	if err := jsonrpc.WriteResult(w, req.ID, result); err != nil {
		log.LogError("Failed to write tools/list response: %v", err)
	}
}

// handleToolCall handles tool execution requests
func (h *Handler) handleToolCall(ctx context.Context, w http.ResponseWriter, req *jsonrpc.Request) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		jsonrpc.WriteError(w, req.ID, jsonrpc.InvalidParams, "Invalid parameters")
		return
	}

	result, err := h.server.HandleToolCall(ctx, params.Name, params.Arguments)
	if err != nil {
		jsonrpc.WriteError(w, req.ID, jsonrpc.InternalError, err.Error())
		return
	}

	response := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": formatToolResult(result),
			},
		},
		"isError": err != nil,
	}

	if err := jsonrpc.WriteResult(w, req.ID, response); err != nil {
		log.LogError("Failed to write tools/call response: %v", err)
	}
}

// formatToolResult formats the tool result for display
func formatToolResult(result any) string {
	// If it's already a string, return it
	if str, ok := result.(string); ok {
		return str
	}

	// If it's a map with output field, return that
	if m, ok := result.(map[string]any); ok {
		if output, exists := m["output"]; exists {
			if str, ok := output.(string); ok {
				return str
			}
		}
	}

	// Otherwise, marshal as JSON
	bytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", result)
	}
	return string(bytes)
}
