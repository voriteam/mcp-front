package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want map[string]any
	}{
		{
			name: "tool call names the requested tool",
			body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"github__get_me","arguments":{}}}`,
			want: map[string]any{"mcp.method.name": "tools/call", "jsonrpc.request.id": "7", "gen_ai.tool.name": "github__get_me"},
		},
		{
			name: "tool call lists its argument names in order",
			body: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"postgres__execute_sql","arguments":{"sql":"select 1","limit":5}}}`,
			want: map[string]any{
				"mcp.method.name":         "tools/call",
				"jsonrpc.request.id":      "8",
				"gen_ai.tool.name":        "postgres__execute_sql",
				"mcp.tool.argument_names": "limit,sql",
			},
		},
		{
			name: "non-object arguments do not spoil the envelope",
			body: `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"x__y","arguments":[1,2]}}`,
			want: map[string]any{"mcp.method.name": "tools/call", "jsonrpc.request.id": "9", "gen_ai.tool.name": "x__y"},
		},
		{
			name: "initialize names the client",
			body: `{"jsonrpc":"2.0","id":"a1","method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-code","version":"2.1.273"}}}`,
			want: map[string]any{
				"mcp.method.name":      "initialize",
				"jsonrpc.request.id":   "a1",
				"mcp.protocol.version": "2025-06-18",
				"mcp.client.name":      "claude-code",
				"mcp.client.version":   "2.1.273",
			},
		},
		{
			name: "notification has no request id",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			want: map[string]any{"mcp.method.name": "notifications/initialized"},
		},
		{
			name: "resource read names the uri",
			body: `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///a"}}`,
			want: map[string]any{"mcp.method.name": "resources/read", "jsonrpc.request.id": "1", "mcp.resource.uri": "file:///a"},
		},
		{
			name: "batch lists its methods",
			body: `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`,
			want: map[string]any{"jsonrpc.batch.size": 2, "mcp.method.name": "tools/list,notifications/initialized"},
		},
		{
			name: "malformed body is flagged",
			body: `{"jsonrpc":`,
			want: map[string]any{"jsonrpc.parse_error": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rpcFields([]byte(tt.body)))
		})
	}
}

func TestRPCFieldsNeverCarriesArgumentValues(t *testing.T) {
	fields := rpcFields([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"postgres__execute_sql","arguments":{"sql":"select secret"}}}`))

	assert.Equal(t, "sql", fields["mcp.tool.argument_names"])
	for _, value := range fields {
		assert.NotContains(t, value, "select secret")
	}
}

func TestPeekJSONBodyReplaysTheBody(t *testing.T) {
	const payload = `{"jsonrpc":"2.0","method":"ping"}`
	req := httptest.NewRequest(http.MethodPost, "/gateway-streamable", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	body, complete := peekJSONBody(req)
	require.True(t, complete)
	assert.Equal(t, payload, string(body))

	replayed, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(replayed))
}

func TestPeekJSONBodyLeavesOversizedBodiesUnparsed(t *testing.T) {
	payload := strings.Repeat("x", maxInspectedBodyBytes+10)
	req := httptest.NewRequest(http.MethodPost, "/gateway-streamable", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	_, complete := peekJSONBody(req)
	assert.False(t, complete)

	replayed, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Len(t, replayed, len(payload))
}

func TestPeekJSONBodyIgnoresNonJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("client_secret=s3cret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	body, _ := peekJSONBody(req)
	assert.Nil(t, body)
}
