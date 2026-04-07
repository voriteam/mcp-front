package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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
