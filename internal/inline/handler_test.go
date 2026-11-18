package inline

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stainless-api/mcp-front/internal/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_ServeHTTP(t *testing.T) {
	// Create a simple test server
	config := Config{
		Description: "Test server",
	}
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			Command:     "echo",
			Args:        []string{"Hello, Test!"},
		},
	}

	server := NewServer("test", config, resolvedTools)
	handler := NewHandler("test", server)

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{
			name:       "invalid JSON",
			method:     http.MethodPost,
			body:       "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "notification",
			method:     http.MethodPost,
			body:       `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "GET has no stream",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test/", bytes.NewReader([]byte(tt.body)))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestHandler_Message_Initialize(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			InputSchema: json.RawMessage(`{"type": "object"}`),
			Command:     "echo",
			Args:        []string{"{{.message}}"},
		},
	}

	server := NewServer("test", Config{Description: "Test server"}, resolvedTools)
	handler := NewHandler("test", server)

	// Create initialize request
	request := jsonrpc.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{}`),
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/test/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Parse response
	var response jsonrpc.Response
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "2.0", response.JSONRPC)
	assert.Equal(t, float64(1), response.ID) // JSON numbers are float64
	assert.Nil(t, response.Error)

	result, ok := response.Result.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "2025-11-25", result["protocolVersion"])
	assert.Contains(t, result, "capabilities")
	assert.Contains(t, result, "serverInfo")
}

func TestHandler_Message_ToolsList(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "tool1",
			Description: "First tool",
			InputSchema: json.RawMessage(`{"type": "object"}`),
			Command:     "echo",
		},
		{
			Name:        "tool2",
			Description: "Second tool",
			InputSchema: json.RawMessage(`{"type": "object", "properties": {"arg": {"type": "string"}}}`),
			Command:     "echo",
		},
	}

	server := NewServer("test", Config{Description: "Test server"}, resolvedTools)
	handler := NewHandler("test", server)

	// Create tools/list request
	request := jsonrpc.Request{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/test/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response jsonrpc.Response
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	result, ok := response.Result.(map[string]any)
	require.True(t, ok)

	tools, ok := result["tools"].([]any)
	require.True(t, ok)
	assert.Len(t, tools, 2)
}

func TestHandler_Message_ToolCall(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			Command:     "echo",
			Args:        []string{"Hello, Test!"},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	handler := NewHandler("test", server)

	// Create tools/call request
	params := map[string]any{
		"name": "echo",
		"arguments": map[string]any{
			"message": "Hello, Test!",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	request := jsonrpc.Request{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsJSON),
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/test/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Parse response
	var response jsonrpc.Response
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Nil(t, response.Error)

	result, ok := response.Result.(map[string]any)
	require.True(t, ok)

	content, ok := result["content"].([]any)
	require.True(t, ok)
	assert.Len(t, content, 1)

	contentItem, ok := content[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "text", contentItem["type"])
	assert.Contains(t, contentItem["text"], "Hello, Test!")
}

func TestHandler_Message_Errors(t *testing.T) {
	server := NewServer("test", Config{}, []ResolvedToolConfig{})
	handler := NewHandler("test", server)

	tests := []struct {
		name           string
		body           string
		expectedStatus int
		expectedError  int
		expectedMsg    string
	}{
		{
			name:           "Invalid JSON",
			body:           `{invalid json`,
			expectedStatus: http.StatusBadRequest, // Invalid JSON returns 400
			expectedError:  -32700,
			expectedMsg:    "Invalid JSON",
		},
		{
			name:           "Unknown method",
			body:           `{"jsonrpc": "2.0", "id": 1, "method": "unknown/method"}`,
			expectedStatus: http.StatusOK, // Valid JSON-RPC errors return 200
			expectedError:  -32601,
			expectedMsg:    "Method not found",
		},
		{
			name:           "Invalid tool call params",
			body:           `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "invalid"}`,
			expectedStatus: http.StatusOK, // Valid JSON-RPC errors return 200
			expectedError:  -32602,
			expectedMsg:    "Invalid parameters",
		},
		{
			name:           "Nonexistent tool",
			body:           `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nonexistent", "arguments": {}}}`,
			expectedStatus: http.StatusOK, // Valid JSON-RPC errors return 200
			expectedError:  -32603,
			expectedMsg:    "tool nonexistent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test/", bytes.NewReader([]byte(tt.body)))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Parse response
			var response jsonrpc.Response
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Nil(t, response.Result)
			require.NotNil(t, response.Error)

			assert.Equal(t, tt.expectedError, response.Error.Code)
			assert.Equal(t, tt.expectedMsg, response.Error.Message)
		})
	}
}

// MockServer implements MCPServer interface for testing
type MockServer struct {
	tools       map[string]Tool
	description string
	callHandler func(ctx context.Context, toolName string, args map[string]any) (any, error)
}

func (m *MockServer) GetCapabilities() ServerCapabilities {
	return ServerCapabilities{Tools: m.tools}
}

func (m *MockServer) HandleToolCall(ctx context.Context, toolName string, args map[string]any) (any, error) {
	if m.callHandler != nil {
		return m.callHandler(ctx, toolName, args)
	}
	return map[string]any{"result": "mock"}, nil
}

func (m *MockServer) GetDescription() string {
	return m.description
}
