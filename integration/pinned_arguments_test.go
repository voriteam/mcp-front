package integration

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPinnedArgumentsDirectMount checks that a server mounted directly at
// /<serverName>/ gets the same treatment as one reached through an aggregate:
// the pinned property is absent from the advertised schema, and the backend
// still receives it on a call that omitted it.
func TestPinnedArgumentsDirectMount(t *testing.T) {
	trace(t, "Starting pinned arguments integration test")

	startMCPFront(t, "config/config.pinned-args-test.json")
	waitForMCPFront(t)

	client := NewMCPStreamableClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create streamable client")
	defer client.Close()

	client.SetAuthToken("streamable-test-token")
	require.NoError(t, client.ConnectToServer("test-streamable"))

	t.Run("pinned property is absent from the advertised schema", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err, "Failed to list tools")

		schema := toolInputSchema(t, result, "echo_arguments")
		properties, ok := schema["properties"].(map[string]any)
		require.True(t, ok, "Expected a properties object, got %v", schema)

		assert.NotContains(t, properties, "headers", "the pinned property's only parent should be gone")
		assert.Contains(t, properties, "text")
		assert.Equal(t, []any{"text"}, schema["required"])
	})

	t.Run("backend receives the pinned value on a call that omitted it", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name":      "echo_arguments",
			"arguments": map[string]any{"text": "hello"},
		})
		require.NoError(t, err, "Failed to call echo_arguments tool")

		assert.Equal(t, map[string]any{
			"text":    "hello",
			"headers": map[string]any{"X-Account-Id": "acct-12345"},
		}, echoedArguments(t, result))
	})

	t.Run("a caller-supplied value is replaced", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name": "echo_arguments",
			"arguments": map[string]any{
				"text":    "hello",
				"headers": map[string]any{"X-Account-Id": "acct-99999"},
			},
		})
		require.NoError(t, err, "Failed to call echo_arguments tool")

		assert.Equal(t, map[string]any{
			"text":    "hello",
			"headers": map[string]any{"X-Account-Id": "acct-12345"},
		}, echoedArguments(t, result))
	})
}

func toolInputSchema(t *testing.T, response map[string]any, toolName string) map[string]any {
	t.Helper()

	result, ok := response["result"].(map[string]any)
	require.True(t, ok, "Expected a result field, got %v", response)
	tools, ok := result["tools"].([]any)
	require.True(t, ok, "Expected a tools array, got %v", result)

	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok || tool["name"] != toolName {
			continue
		}
		schema, ok := tool["inputSchema"].(map[string]any)
		require.True(t, ok, "Expected an inputSchema object, got %v", tool)
		return schema
	}

	t.Fatalf("tool %s not found in %v", toolName, tools)
	return nil
}

// echoedArguments reads back the arguments the mock backend received, which it
// returns as JSON text content.
func echoedArguments(t *testing.T, response map[string]any) map[string]any {
	t.Helper()

	result, ok := response["result"].(map[string]any)
	require.True(t, ok, "Expected a result field, got %v", response)
	content, ok := result["content"].([]any)
	require.True(t, ok && len(content) > 0, "Expected content, got %v", result)
	first, ok := content[0].(map[string]any)
	require.True(t, ok, "Expected a content object, got %v", content[0])
	text, ok := first["text"].(string)
	require.True(t, ok, "Expected text content, got %v", first)

	var arguments map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &arguments), "backend echoed %q", text)
	return arguments
}
