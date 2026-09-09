package builtin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func echoTool(name string, seen *json.RawMessage, caller *string) Tool {
	return Tool{
		Name:        name,
		Description: name + " description",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
		Handler: func(_ context.Context, userEmail string, args json.RawMessage) (*mcp.CallToolResult, error) {
			*seen = args
			*caller = userEmail
			return mcp.NewToolResultText("ok"), nil
		},
	}
}

func TestListTools(t *testing.T) {
	var seen json.RawMessage
	var caller string
	c := NewClient("gtm", "ae@vori.com", []Tool{
		echoTool("first", &seen, &caller),
		echoTool("second", &seen, &caller),
	})

	res, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, res.Tools, 2)

	assert.Equal(t, "first", res.Tools[0].Name, "declaration order is preserved")
	assert.Equal(t, "second", res.Tools[1].Name)
	assert.Equal(t, "first description", res.Tools[0].Description)
	assert.JSONEq(t,
		`{"type":"object","properties":{"q":{"type":"string"}}}`,
		string(res.Tools[0].RawInputSchema))
	assert.Empty(t, res.NextCursor, "empty cursor ends the aggregate's pagination loop")

	// A tool carrying both schemas fails to marshal in mcp-go.
	assert.Empty(t, res.Tools[0].InputSchema.Type)
	_, err = json.Marshal(res.Tools[0])
	require.NoError(t, err)
}

func TestCallTool(t *testing.T) {
	t.Run("dispatches with arguments and caller", func(t *testing.T) {
		var seen json.RawMessage
		var caller string
		c := NewClient("gtm", "ae@vori.com", []Tool{echoTool("go", &seen, &caller)})

		req := mcp.CallToolRequest{}
		req.Params.Name = "go"
		req.Params.Arguments = map[string]any{"q": "hello"}

		res, err := c.CallTool(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.JSONEq(t, `{"q":"hello"}`, string(seen))
		assert.Equal(t, "ae@vori.com", caller)
	})

	t.Run("unknown tool is a tool error", func(t *testing.T) {
		c := NewClient("gtm", "ae@vori.com", nil)
		req := mcp.CallToolRequest{}
		req.Params.Name = "nope"

		res, err := c.CallTool(context.Background(), req)
		require.NoError(t, err, "an unknown name must not fail the connection")
		require.NotNil(t, res)
		assert.True(t, res.IsError)
	})
}

func TestLifecycleIsInert(t *testing.T) {
	c := NewClient("gtm", "ae@vori.com", nil)
	ctx := context.Background()

	require.NoError(t, c.Start(ctx))
	require.NoError(t, c.Ping(ctx))

	init, err := c.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	assert.Equal(t, "gtm", init.ServerInfo.Name)
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, init.ProtocolVersion)

	require.NoError(t, c.Close())
}
