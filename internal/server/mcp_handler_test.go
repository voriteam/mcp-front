package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestMCPHandler(serverName string, serverConfig *config.MCPClientConfig) *MCPHandler {
	return NewMCPHandler(serverName, serverConfig, func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
		if userEmail == "" {
			return "", fmt.Errorf("no user")
		}
		return "test-token-for-" + serviceName, nil
	})
}

func TestHandleStreamablePost(t *testing.T) {
	t.Run("JSON response", func(t *testing.T) {
		// Create a mock backend server
		backendCalled := false
		var capturedBody []byte
		var capturedHeaders http.Header

		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled = true
			capturedHeaders = r.Header
			capturedBody, _ = io.ReadAll(r.Body)

			// Return a JSON response
			response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Custom-Header", "test-value")
			_ = json.NewEncoder(w).Encode(response)
		}))
		defer backendServer.Close()

		// Create handler for streamable-http server
		streamableConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeStreamable,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
			Timeout: 5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		// Create test request
		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
			Params:  json.RawMessage(`{"key": "value"}`),
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		// Handle request
		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		// Verify backend was called
		assert.True(t, backendCalled, "Backend should have been called")

		// Verify request forwarding
		assert.Equal(t, "Bearer test-token", capturedHeaders.Get("Authorization"))
		assert.Equal(t, "application/json", capturedHeaders.Get("Content-Type"))
		assert.Equal(t, "application/json, text/event-stream", capturedHeaders.Get("Accept"))
		assert.Equal(t, body, capturedBody)

		// Verify response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "test-value", rec.Header().Get("X-Custom-Header"))

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(1), response.ID)
	})

	t.Run("SSE stream response", func(t *testing.T) {
		messages := []string{
			"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\"Hello\"}}\n\n",
			"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":\"World\"}}\n\n",
		}

		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return SSE stream
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			flusher := w.(http.Flusher)
			for _, msg := range messages {
				_, _ = w.Write([]byte(msg))
				flusher.Flush()
			}
		}))
		defer backendServer.Close()

		streamableConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeStreamable,
			Timeout:       5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		// Verify SSE response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))

		// Verify all messages were streamed
		bodyStr := rec.Body.String()
		for _, msg := range messages {
			assert.Contains(t, bodyStr, strings.TrimSpace(msg))
		}
	})

	t.Run("backend error", func(t *testing.T) {
		streamableConfig := &config.MCPClientConfig{
			URL:           "http://localhost:1", // Invalid port
			TransportType: config.MCPClientTypeStreamable,
			Timeout:       100 * time.Millisecond,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader([]byte("{}")))
		rec := httptest.NewRecorder()

		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "backend request failed", response.Error.Message)
	})
}

func TestHandleStreamableGet(t *testing.T) {
	t.Run("successful SSE stream", func(t *testing.T) {
		// Create a mock SSE backend
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify Accept header
			assert.Equal(t, "text/event-stream", r.Header.Get("Accept"))

			// Send SSE response
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			// Send some SSE data
			_, _ = w.Write([]byte("data: {\"type\":\"connected\"}\n\n"))
			w.(http.Flusher).Flush()
		}))
		defer backend.Close()

		// Configure client
		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
			Timeout: 5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request with Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()

		// Call the function
		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Verify response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "data: {\"type\":\"connected\"}")
	})

	t.Run("missing Accept header", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request without Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		rec := httptest.NewRecorder()

		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Should return 406 Not Acceptable
		assert.Equal(t, http.StatusNotAcceptable, rec.Code)
		assert.Contains(t, rec.Body.String(), "GET requests must accept text/event-stream")
	})

	t.Run("wrong Accept header", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request with wrong Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()

		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Should return 406 Not Acceptable
		assert.Equal(t, http.StatusNotAcceptable, rec.Code)
		assert.Contains(t, rec.Body.String(), "GET requests must accept text/event-stream")
	})
}

func TestStreamableTransportRouting(t *testing.T) {
	t.Run("POST request routes to handleStreamablePost", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": "ok"}`))
		}))
		defer backend.Close()

		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `{"result": "ok"}`)
	})

	t.Run("GET request routes to handleStreamableGet", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: test\n\n"))
		}))
		defer backend.Close()

		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	})

	t.Run("unsupported method returns 405", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodPut, "/test-streamable", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}
