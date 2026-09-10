package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestForwardStreamablePostToBackend_SSESessionHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Mcp-Session-Id", "sess-42")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"))
		w.(http.Flusher).Flush()
	}))
	defer backend.Close()

	cfg := &config.MCPClientConfig{
		URL:     backend.URL,
		Timeout: 5 * time.Second,
	}

	req := httptest.NewRequest(http.MethodPost, "/test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	rec := httptest.NewRecorder()

	forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, "sess-42", rec.Header().Get("Mcp-Session-Id"), "Mcp-Session-Id header must be forwarded in SSE responses")
	assert.Contains(t, rec.Body.String(), `"result"`)
}

func TestForwardStreamablePostToBackend_PinnedArguments(t *testing.T) {
	pinnedConfig := func(backendURL string) *config.MCPClientConfig {
		return &config.MCPClientConfig{
			TransportType: config.MCPClientTypeStreamable,
			URL:           backendURL,
			Timeout:       5 * time.Second,
			Options:       &config.Options{PinnedArguments: map[string]string{"headers.X-Account-Id": "12345"}},
		}
	}

	t.Run("sets the pinned value on a forwarded tools/call", func(t *testing.T) {
		var received string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			received = string(body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}))
		defer backend.Close()

		req := httptest.NewRequest(http.MethodPost, "/billing/", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"page":2}}}`))
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, pinnedConfig(backend.URL))

		assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"page":2,"headers":{"X-Account-Id":"12345"}}}}`, received)
	})

	t.Run("strips the pinned property from a JSON tools/list response", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_invoices","inputSchema":{"type":"object","properties":{"headers":{"type":"object","properties":{"X-Account-Id":{"type":"string"}},"required":["X-Account-Id"]},"page":{"type":"integer"}},"required":["headers","page"]}}]}}`))
		}))
		defer backend.Close()

		req := httptest.NewRequest(http.MethodPost, "/billing/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, pinnedConfig(backend.URL))

		assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_invoices","inputSchema":{"type":"object","properties":{"page":{"type":"integer"}},"required":["page"]}}]}}`, rec.Body.String())
		assert.Equal(t, strconv.Itoa(rec.Body.Len()), rec.Header().Get("Content-Length"))
	})

	t.Run("strips the pinned property from an SSE tools/list response", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"list_invoices\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"headers\":{\"type\":\"object\",\"properties\":{\"X-Account-Id\":{\"type\":\"string\"}}},\"page\":{\"type\":\"integer\"}}}}]}}\n\n"))
		}))
		defer backend.Close()

		req := httptest.NewRequest(http.MethodPost, "/billing/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, pinnedConfig(backend.URL))

		assert.NotContains(t, rec.Body.String(), "X-Account-Id")
		assert.Contains(t, rec.Body.String(), `"page"`)
	})
}
