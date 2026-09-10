package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingClient captures what the decorator forwards to the backend.
type recordingClient struct {
	MCPClientInterface
	tools    []mcp.Tool
	lastCall mcp.CallToolRequest
}

func (c *recordingClient) ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	return &mcp.ListToolsResult{Tools: c.tools}, nil
}

func (c *recordingClient) CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	c.lastCall = request
	return &mcp.CallToolResult{}, nil
}

func newRecordingClient() *recordingClient {
	return &recordingClient{
		tools: []mcp.Tool{
			{
				Name: "list_invoices",
				InputSchema: mcp.ToolInputSchema{
					Type: "object",
					Properties: map[string]any{
						"org":  map[string]any{"type": "string"},
						"page": map[string]any{"type": "integer"},
					},
					Required: []string{"org", "page"},
				},
			},
			{
				Name: "ping",
				InputSchema: mcp.ToolInputSchema{
					Type:       "object",
					Properties: map[string]any{"page": map[string]any{"type": "integer"}},
				},
			},
		},
	}
}

func pinnedConfig(pinned map[string]string) *config.MCPClientConfig {
	return &config.MCPClientConfig{
		TransportType: config.MCPClientTypeStreamable,
		URL:           "https://example.com/mcp",
		Options:       &config.Options{PinnedArguments: pinned},
	}
}

func TestWithPinnedArgumentsListTools(t *testing.T) {
	inner := newRecordingClient()
	wrapped := withPinnedArguments(inner, pinnedConfig(map[string]string{"org": "12345"}))

	result, err := wrapped.ListTools(context.Background(), mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, result.Tools, 2)

	assert.NotContains(t, result.Tools[0].InputSchema.Properties, "org")
	assert.Contains(t, result.Tools[0].InputSchema.Properties, "page")
	assert.Equal(t, []string{"page"}, result.Tools[0].InputSchema.Required)
	assert.Contains(t, result.Tools[1].InputSchema.Properties, "page")
}

func TestWithPinnedArgumentsCallTool(t *testing.T) {
	tests := []struct {
		name      string
		arguments any
		expected  map[string]any
	}{
		{
			name:      "absent path is created",
			arguments: map[string]any{"page": float64(2)},
			expected:  map[string]any{"page": float64(2), "headers": map[string]any{"X-Account-Id": "12345"}},
		},
		{
			name:      "caller value is overwritten",
			arguments: map[string]any{"headers": map[string]any{"X-Account-Id": "99999"}},
			expected:  map[string]any{"headers": map[string]any{"X-Account-Id": "12345"}},
		},
		{
			name:      "nil arguments",
			arguments: nil,
			expected:  map[string]any{"headers": map[string]any{"X-Account-Id": "12345"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := newRecordingClient()
			wrapped := withPinnedArguments(inner, pinnedConfig(map[string]string{"headers.X-Account-Id": "12345"}))

			var request mcp.CallToolRequest
			request.Params.Name = "list_invoices"
			request.Params.Arguments = tt.arguments

			_, err := wrapped.CallTool(context.Background(), request)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, inner.lastCall.GetArguments())
			assert.Equal(t, "list_invoices", inner.lastCall.Params.Name)
		})
	}
}

func TestWithPinnedArgumentsSkipsUnconfiguredServers(t *testing.T) {
	inner := newRecordingClient()

	assert.Same(t, inner, withPinnedArguments(inner, pinnedConfig(nil)))
	assert.Same(t, inner, withPinnedArguments(inner, &config.MCPClientConfig{}))
	assert.Same(t, inner, withPinnedArguments(inner, nil))
}

func TestWithPinnedArgumentsRawSchema(t *testing.T) {
	inner := newRecordingClient()
	inner.tools = []mcp.Tool{{
		Name:           "list_invoices",
		RawInputSchema: json.RawMessage(`{"type":"object","properties":{"org":{"type":"string"}},"required":["org"]}`),
	}}
	wrapped := withPinnedArguments(inner, pinnedConfig(map[string]string{"org": "12345"}))

	result, err := wrapped.ListTools(context.Background(), mcp.ListToolsRequest{})
	require.NoError(t, err)

	assert.JSONEq(t, `{"type":"object","properties":{}}`, string(result.Tools[0].RawInputSchema))
}
