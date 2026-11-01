package integration

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateBasic(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
		},
		"test-streamable": map[string]any{
			"transportType": "streamable-http",
			"url":           "http://localhost:3002",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"discovery": map[string]any{
				"timeout":  "10s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	t.Run("tool_discovery", func(t *testing.T) {
		err := client.ConnectToServer("mcp")
		require.NoError(t, err, "Failed to connect to aggregate endpoint")

		result, err := client.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err, "Failed to list tools")
		require.NotContains(t, result, "error")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		tools, ok := resultData["tools"].([]any)
		require.True(t, ok, "Expected tools array")

		toolNames := make(map[string]bool)
		for _, tool := range tools {
			toolMap, ok := tool.(map[string]any)
			if ok {
				if name, ok := toolMap["name"].(string); ok {
					toolNames[name] = true
				}
			}
		}

		assert.True(t, toolNames["test-sse.echo_text"], "Missing test-sse.echo_text")
		assert.True(t, toolNames["test-sse.sample_stream"], "Missing test-sse.sample_stream")
		assert.True(t, toolNames["test-streamable.get_time"], "Missing test-streamable.get_time")
		assert.True(t, toolNames["test-streamable.echo_streamable"], "Missing test-streamable.echo_streamable")
		assert.Equal(t, 4, len(toolNames), "Expected exactly 4 tools, got: %v", toolNames)
	})

	t.Run("tool_call_sse_backend", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name":      "test-sse.echo_text",
			"arguments": map[string]any{"text": "hello aggregate"},
		})
		require.NoError(t, err, "Failed to call tool")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		content, ok := resultData["content"].([]any)
		require.True(t, ok, "Expected content array")
		require.NotEmpty(t, content)
		textContent, ok := content[0].(map[string]any)
		require.True(t, ok, "Expected text content object")
		assert.Equal(t, "hello aggregate", textContent["text"])
	})

	t.Run("tool_call_streamable_backend", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name":      "test-streamable.echo_streamable",
			"arguments": map[string]any{"text": "world"},
		})
		require.NoError(t, err, "Failed to call tool")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		content, ok := resultData["content"].([]any)
		require.True(t, ok, "Expected content array")
		require.NotEmpty(t, content)
		textContent, ok := content[0].(map[string]any)
		require.True(t, ok, "Expected text content object")
		assert.Contains(t, textContent["text"], "Echo: world")
	})
}

func TestAggregatePartialFailure(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
		},
		"bad-backend": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:9999/sse",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"servers":       []string{"test-sse", "bad-backend"},
			"discovery": map[string]any{
				"timeout":  "3s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-partial-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	err := client.ConnectToServer("mcp")
	require.NoError(t, err, "Failed to connect to aggregate endpoint")

	result, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Failed to list tools")
	require.NotContains(t, result, "error")

	resultData, ok := result["result"].(map[string]any)
	require.True(t, ok, "Expected result field")
	tools, ok := resultData["tools"].([]any)
	require.True(t, ok, "Expected tools array")

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if ok {
			if name, ok := toolMap["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}

	assert.True(t, toolNames["test-sse.echo_text"], "Missing test-sse.echo_text")
	assert.True(t, toolNames["test-sse.sample_stream"], "Missing test-sse.sample_stream")

	for name := range toolNames {
		assert.NotContains(t, name, "bad-backend", "Should not have tools from unreachable backend")
	}
}

func TestAggregateToolFilter(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
			"options": map[string]any{
				"toolFilter": map[string]any{
					"mode": "block",
					"list": []string{"sample_stream"},
				},
			},
		},
		"test-streamable": map[string]any{
			"transportType": "streamable-http",
			"url":           "http://localhost:3002",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"discovery": map[string]any{
				"timeout":  "10s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-filter-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	err := client.ConnectToServer("mcp")
	require.NoError(t, err, "Failed to connect to aggregate endpoint")

	result, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Failed to list tools")
	require.NotContains(t, result, "error")

	resultData, ok := result["result"].(map[string]any)
	require.True(t, ok, "Expected result field")
	tools, ok := resultData["tools"].([]any)
	require.True(t, ok, "Expected tools array")

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if ok {
			if name, ok := toolMap["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}

	assert.True(t, toolNames["test-sse.echo_text"], "echo_text should be present")
	assert.False(t, toolNames["test-sse.sample_stream"], "sample_stream should be blocked by filter")

	assert.True(t, toolNames["test-streamable.get_time"], "get_time should be unaffected")
	assert.True(t, toolNames["test-streamable.echo_streamable"], "echo_streamable should be unaffected")
}

func TestAggregateSupersedes(t *testing.T) {
	const cacheTTL = 2 * time.Second
	mcpServers := map[string]any{
		"notes": map[string]any{
			"transportType":     "sse",
			"url":               "http://localhost:3001/sse",
			"requiresUserToken": true,
			"userAuthentication": map[string]any{
				"type":         "manual",
				"displayName":  "Notes",
				"instructions": "Enter your notes token",
			},
		},
		"notes-read-only": map[string]any{
			"transportType": "streamable-http",
			"url":           "http://localhost:3002",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"discovery": map[string]any{
				"timeout":  "1s",
				"cacheTtl": cacheTTL.String(),
			},
			"supersedes": map[string]any{"notes": []string{"notes-read-only"}},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-supersedes-test", testOAuthConfigFromEnv(), mcpServers)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
	)
	waitForMCPFront(t)

	accessToken := getOAuthAccessToken(t, "http://localhost:8080/mcp")
	connect := func(t *testing.T) *MCPSSEClient {
		client := NewMCPSSEClient("http://localhost:8080")
		client.SetAuthToken(accessToken)
		require.NoError(t, client.ConnectToServer("mcp"))
		t.Cleanup(client.Close)
		return client
	}
	readOnlyTools := []string{"notes-read-only.echo_streamable", "notes-read-only.get_time"}
	fullTools := []string{"notes.echo_text", "notes.sample_stream"}

	client := connect(t)
	require.Equal(t, readOnlyTools, aggregateToolNames(t, client), "a user without a notes token sees the read-only backend")

	submitTokenForm(t, "set", url.Values{"service": {"notes"}, "token": {"notes-token"}})
	time.Sleep(cacheTTL + 500*time.Millisecond)

	assert.Equal(t, fullTools, aggregateToolNames(t, client), "the connected session swaps the read-only backend for the full one")

	result, err := client.SendMCPRequest("tools/call", map[string]any{"name": "notes-read-only.get_time", "arguments": map[string]any{}})
	require.NoError(t, err)
	rpcErr, ok := result["error"].(map[string]any)
	require.True(t, ok, "calling a hidden tool must fail, got %v", result)
	assert.Contains(t, rpcErr["message"], "not found")

	result, err = client.SendMCPRequest("tools/call", map[string]any{"name": "notes.echo_text", "arguments": map[string]any{"text": "hi"}})
	require.NoError(t, err)
	assert.NotContains(t, result, "error")

	submitTokenForm(t, "delete", url.Values{"service": {"notes"}})
	time.Sleep(cacheTTL + 500*time.Millisecond)

	assert.Equal(t, readOnlyTools, aggregateToolNames(t, connect(t)), "a new session after disconnecting sees the read-only backend again")
}

func aggregateToolNames(t *testing.T, client *MCPSSEClient) []string {
	t.Helper()
	result, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err)
	resultData, ok := result["result"].(map[string]any)
	require.True(t, ok, "expected a result, got %v", result)
	tools, ok := resultData["tools"].([]any)
	require.True(t, ok, "expected a tools array, got %v", resultData)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	sort.Strings(names)
	return names
}

func submitTokenForm(t *testing.T, action string, form url.Values) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browser := &http.Client{Jar: jar}

	resp, err := browser.Get("http://localhost:8080/my/tokens")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	form.Set("csrf_token", extractCSRFToken(t, string(body)))

	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = browser.PostForm("http://localhost:8080/my/tokens/"+action, form)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "type=success")
}
