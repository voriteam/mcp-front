package aggregate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixtures under testdata/tools_list hold tools/list results as real backends
// return them. Decoding them into mcp.ListToolsResult is what mcp-go's client
// does with a backend response.
func loadToolsListFixture(t *testing.T, backend string) []mcp.Tool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "tools_list", backend+".json"))
	require.NoError(t, err)
	var result mcp.ListToolsResult
	require.NoError(t, json.Unmarshal(raw, &result))
	require.NotEmpty(t, result.Tools)
	return result.Tools
}

type wireTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func listToolsOverWire(t *testing.T, srv *Server, ctx context.Context) ([]byte, map[string]wireTool) {
	t.Helper()
	resp := srv.mcpServer.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	encoded, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed struct {
		Result struct {
			Tools []wireTool `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(encoded, &parsed))
	require.Nil(t, parsed.Error)

	tools := make(map[string]wireTool, len(parsed.Result.Tools))
	for _, tool := range parsed.Result.Tools {
		tools[tool.Name] = tool
	}
	return encoded, tools
}

func listToolsForNewSession(t *testing.T, srv *Server) ([]byte, map[string]wireTool) {
	t.Helper()
	_, ctx := registerSyncTestSession(t, srv, "wire-"+t.Name())
	return listToolsOverWire(t, srv, ctx)
}

func withDelimiter(cfg *ServerConfig) {
	cfg.Delimiter = "__"
}

func streamlined(cfg *ServerConfig) {
	withDelimiter(cfg)
	cfg.StreamlineResponses = true
}

func walkSchemaNodes(path string, schema map[string]any, visit func(path string, node map[string]any)) {
	visit(path, schema)
	for key, value := range schema {
		switch key {
		case "properties", "$defs":
			if children, ok := value.(map[string]any); ok {
				for name, child := range children {
					if node, ok := child.(map[string]any); ok {
						walkSchemaNodes(path+"."+key+"."+name, node, visit)
					}
				}
			}
		case "items", "anyOf", "oneOf", "allOf":
			switch node := value.(type) {
			case map[string]any:
				walkSchemaNodes(path+"."+key, node, visit)
			case []any:
				for _, item := range node {
					if child, ok := item.(map[string]any); ok {
						walkSchemaNodes(path+"."+key+"[]", child, visit)
					}
				}
			}
		}
	}
}

func TestStreamlinedToolsListOverWire(t *testing.T) {
	for _, backend := range []string{"github", "linear", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			fixture := loadToolsListFixture(t, backend)
			plain := newTestServerWith(t, map[string]*mockTransport{backend: newMockTransport(fixture)}, withDelimiter)
			trimmed := newTestServerWith(t, map[string]*mockTransport{backend: newMockTransport(fixture)}, streamlined)

			rawWire, rawTools := listToolsForNewSession(t, plain)
			session, ctx := registerSyncTestSession(t, trimmed, "wire-"+t.Name())
			trimmedWire, trimmedTools := listToolsOverWire(t, trimmed, ctx)
			require.Len(t, rawTools, len(fixture))
			require.Len(t, trimmedTools, len(fixture))
			assert.Less(t, len(trimmedWire), len(rawWire))
			t.Logf("%s tools/list: %d bytes raw, %d bytes streamlined (%.0f%% smaller)",
				backend, len(rawWire), len(trimmedWire), 100*(1-float64(len(trimmedWire))/float64(len(rawWire))))

			for name, tool := range trimmedTools {
				assert.LessOrEqual(t, len(tool.Description), maxDescriptionLength, name)
				walkSchemaNodes(name, tool.InputSchema, func(path string, node map[string]any) {
					for key := range node {
						assert.False(t, droppedSchemaKeys[key] || strings.HasPrefix(key, "x-"), "%s still has %s", path, key)
					}
					if desc, ok := node["description"].(string); ok {
						assert.LessOrEqual(t, len(desc), maxPropertyDescriptionLength, path)
						assert.NotContains(t, desc, "\n", path)
					}
				})
			}

			trimmed.syncSessionTools(ctx, session)
			assert.Empty(t, session.notifications, "re-streamlining the same tools must not look like a change")
		})
	}
}

func TestStreamlinedSchemaKeepsWhatModelsNeed(t *testing.T) {
	srv := newTestServerWith(t, map[string]*mockTransport{
		"linear":   newMockTransport(loadToolsListFixture(t, "linear")),
		"postgres": newMockTransport(loadToolsListFixture(t, "postgres")),
	}, streamlined)
	_, tools := listToolsForNewSession(t, srv)

	saveIssue := properties(t, tools["linear__save_issue"].InputSchema)
	assert.Equal(t, map[string]any{
		"type":        "string",
		"format":      "date-time",
		"description": "ISO-8601 timestamp when the SLA will breach.",
	}, saveIssue["slaBreachesAt"])
	assert.Equal(t, map[string]any{
		"type":        "string",
		"enum":        []any{"all", "onlyBusinessDays"},
		"description": "SLA day counting type: \"all\" or \"onlyBusinessDays\".",
	}, saveIssue["slaType"])
	assert.Equal(t, "Label names or IDs as a JSON array of strings (e.g. [\"Bug\", \"Urgent\"]) to add.",
		saveIssue["addLabels"].(map[string]any)["description"])
	assert.Equal(t, []any{"string", "null"}, saveIssue["assignee"].(map[string]any)["type"])

	links := properties(t, saveIssue["links"].(map[string]any)["items"].(map[string]any))
	assert.Equal(t, map[string]any{"type": "string", "format": "uri"}, links["url"])
	assert.Equal(t, map[string]any{"type": "string"}, links["title"])

	patch := saveIssue["patch"].(map[string]any)
	assert.NotContains(t, patch, "maxItems")
	ops := patch["items"].(map[string]any)["oneOf"].([]any)
	require.Len(t, ops, 6)
	assert.Equal(t, map[string]any{"type": "string", "description": "Exact text to replace."},
		properties(t, ops[0].(map[string]any))["old_string"])

	listIssues := tools["linear__list_issues"].InputSchema
	assert.NotContains(t, listIssues, "additionalProperties")
	limit := properties(t, listIssues)["limit"].(map[string]any)
	assert.Equal(t, float64(50), limit["default"])
	assert.NotContains(t, limit, "maximum")
	assert.Equal(t, "Completed after: ISO-8601 date/duration (e.g., -P1D).",
		properties(t, listIssues)["completedAt"].(map[string]any)["description"])
	assert.Len(t, properties(t, listIssues)["fields"].(map[string]any)["items"].(map[string]any)["enum"], 39)

	listTables := tools["postgres__list_tables"].InputSchema
	assert.Equal(t, map[string]any{
		"type":        "string",
		"default":     "detailed",
		"description": "Optional: Use 'simple' for names only or 'detailed' for full info.",
	}, properties(t, listTables)["output_format"])
	assert.Equal(t, []any{"sql"}, tools["postgres__execute_sql"].InputSchema["required"])
}

func TestToolsListWithoutStreamliningKeepsSchemasIntact(t *testing.T) {
	srv := newTestServerWith(t, map[string]*mockTransport{
		"linear": newMockTransport(loadToolsListFixture(t, "linear")),
	}, withDelimiter)
	_, tools := listToolsForNewSession(t, srv)

	saveIssue := tools["linear__save_issue"].InputSchema
	assert.Equal(t, false, saveIssue["additionalProperties"])
	sla := properties(t, saveIssue)["slaBreachesAt"].(map[string]any)
	assert.Contains(t, sla["anyOf"].([]any)[0], "pattern")
	assert.Equal(t, "ISO-8601 timestamp when the SLA will breach. On update, pass null to remove the SLA", sla["description"])
}

func TestStreamliningAppliesToToolsWithRawSchemas(t *testing.T) {
	tool := mcp.Tool{
		Name:           "create_onboarding_link",
		RawInputSchema: json.RawMessage(`{"type":"object","properties":{"email":{"type":"string","format":"email","pattern":"^.+@.+$","description":"Recipient email address. Must belong to the merchant."}},"required":["email"],"additionalProperties":false}`),
	}
	srv := newTestServerWith(t, map[string]*mockTransport{"gtm": newMockTransport([]mcp.Tool{tool})}, streamlined)
	_, tools := listToolsForNewSession(t, srv)

	assert.Equal(t, map[string]any{
		"type": "object",
		"properties": map[string]any{
			"email": map[string]any{"type": "string", "format": "email", "description": "Recipient email address."},
		},
		"required": []any{"email"},
	}, tools["gtm__create_onboarding_link"].InputSchema)
}
