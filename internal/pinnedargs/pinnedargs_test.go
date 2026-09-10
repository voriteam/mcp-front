package pinnedargs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{name: "single segment", path: "account", expected: []string{"account"}},
		{name: "nested segments", path: "headers.X-Account-Id", expected: []string{"headers", "X-Account-Id"}},
		{name: "three segments", path: "a.b.c", expected: []string{"a", "b", "c"}},
		{name: "escaped dot is literal", path: `headers.X\.Id`, expected: []string{"headers", "X.Id"}},
		{name: "escaped backslash", path: `a\\b.c`, expected: []string{`a\b`, "c"}},
		{name: "trailing backslash kept", path: `a\`, expected: []string{`a\`}},
		{name: "empty segment", path: "a..b", expected: []string{"a", "", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitPath(tt.path); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("SplitPath(%q) = %#v, want %#v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestSetApply(t *testing.T) {
	tests := []struct {
		name     string
		set      Set
		args     any
		expected map[string]any
	}{
		{
			name:     "absent path is created",
			set:      Set{"org": "12345"},
			args:     map[string]any{"query": "select 1"},
			expected: map[string]any{"query": "select 1", "org": "12345"},
		},
		{
			name:     "caller value is overwritten",
			set:      Set{"org": "12345"},
			args:     map[string]any{"org": "99999"},
			expected: map[string]any{"org": "12345"},
		},
		{
			name:     "nested path creates intermediates",
			set:      Set{"headers.X-Account-Id": "12345"},
			args:     map[string]any{"query": "select 1"},
			expected: map[string]any{"query": "select 1", "headers": map[string]any{"X-Account-Id": "12345"}},
		},
		{
			name:     "nested path keeps siblings",
			set:      Set{"headers.X-Account-Id": "12345"},
			args:     map[string]any{"headers": map[string]any{"X-Trace": "abc"}},
			expected: map[string]any{"headers": map[string]any{"X-Trace": "abc", "X-Account-Id": "12345"}},
		},
		{
			name:     "nil arguments",
			set:      Set{"org": "12345"},
			args:     nil,
			expected: map[string]any{"org": "12345"},
		},
		{
			name:     "raw json arguments",
			set:      Set{"org": "12345"},
			args:     json.RawMessage(`{"query":"select 1"}`),
			expected: map[string]any{"query": "select 1", "org": "12345"},
		},
		{
			name:     "non-object argument replaced by pinned object",
			set:      Set{"org": "12345"},
			args:     json.RawMessage(`["a"]`),
			expected: map[string]any{"org": "12345"},
		},
		{
			name:     "scalar at path becomes an object",
			set:      Set{"headers.X-Account-Id": "12345"},
			args:     map[string]any{"headers": "nonsense"},
			expected: map[string]any{"headers": map[string]any{"X-Account-Id": "12345"}},
		},
		{
			name:     "multiple paths",
			set:      Set{"a.b": "1", "c": "2"},
			args:     nil,
			expected: map[string]any{"a": map[string]any{"b": "1"}, "c": "2"},
		},
		{
			name:     "empty set leaves arguments alone",
			set:      Set{},
			args:     map[string]any{"query": "select 1"},
			expected: map[string]any{"query": "select 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.set.Apply(tt.args); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("Apply():\ngot:  %#v\nwant: %#v", got, tt.expected)
			}
		})
	}
}

func TestSetRewriteRawSchema(t *testing.T) {
	tests := []struct {
		name     string
		set      Set
		schema   string
		expected string
	}{
		{
			name:     "removes property and required entry",
			set:      Set{"org": ""},
			schema:   `{"type":"object","properties":{"org":{"type":"string"},"query":{"type":"string"}},"required":["org","query"]}`,
			expected: `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`,
		},
		{
			name:     "drops required entirely when it empties",
			set:      Set{"org": ""},
			schema:   `{"type":"object","properties":{"org":{"type":"string"}},"required":["org"]}`,
			expected: `{"type":"object","properties":{}}`,
		},
		{
			name:     "removes nested property but keeps its siblings",
			set:      Set{"headers.X-Account-Id": ""},
			schema:   `{"type":"object","properties":{"headers":{"type":"object","properties":{"X-Account-Id":{"type":"string"},"X-Trace":{"type":"string"}},"required":["X-Account-Id"]}},"required":["headers"]}`,
			expected: `{"type":"object","properties":{"headers":{"type":"object","properties":{"X-Trace":{"type":"string"}}}},"required":["headers"]}`,
		},
		{
			name:     "prunes an ancestor left with no properties",
			set:      Set{"headers.X-Account-Id": ""},
			schema:   `{"type":"object","properties":{"headers":{"type":"object","properties":{"X-Account-Id":{"type":"string"}},"required":["X-Account-Id"]},"query":{"type":"string"}},"required":["headers","query"]}`,
			expected: `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`,
		},
		{
			name:     "schema lacking the path is unchanged",
			set:      Set{"org": ""},
			schema:   `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`,
			expected: `{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`,
		},
		{
			name:     "nested path missing its parent is unchanged",
			set:      Set{"headers.X-Account-Id": ""},
			schema:   `{"type":"object","properties":{"query":{"type":"string"}}}`,
			expected: `{"type":"object","properties":{"query":{"type":"string"}}}`,
		},
		{
			name:     "escaped dot addresses one property",
			set:      Set{`X\.Id`: ""},
			schema:   `{"type":"object","properties":{"X.Id":{"type":"string"},"query":{"type":"string"}}}`,
			expected: `{"type":"object","properties":{"query":{"type":"string"}}}`,
		},
		{
			name:     "malformed schema is returned as-is",
			set:      Set{"org": ""},
			schema:   `not json`,
			expected: `not json`,
		},
		{
			name:     "empty set is a no-op",
			set:      Set{},
			schema:   `{"type":"object","properties":{"org":{"type":"string"}}}`,
			expected: `{"type":"object","properties":{"org":{"type":"string"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.set.RewriteRawSchema(json.RawMessage(tt.schema))
			assertJSONEqual(t, string(got), tt.expected)
		})
	}
}

func TestSetRewriteTool(t *testing.T) {
	t.Run("rewrites the typed input schema", func(t *testing.T) {
		tool := mcp.Tool{
			Name: "list_invoices",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"headers": map[string]any{
						"type":       "object",
						"properties": map[string]any{"X-Account-Id": map[string]any{"type": "string"}},
						"required":   []any{"X-Account-Id"},
					},
					"page": map[string]any{"type": "integer"},
				},
				Required: []string{"headers", "page"},
			},
		}

		Set{"headers.X-Account-Id": "12345"}.RewriteTool(&tool)

		if _, present := tool.InputSchema.Properties["headers"]; present {
			t.Error("headers should have been pruned once it had no properties left")
		}
		if _, present := tool.InputSchema.Properties["page"]; !present {
			t.Error("page should be untouched")
		}
		if !reflect.DeepEqual(tool.InputSchema.Required, []string{"page"}) {
			t.Errorf("required = %#v, want [page]", tool.InputSchema.Required)
		}
	})

	t.Run("rewrites a raw input schema", func(t *testing.T) {
		tool := mcp.Tool{
			Name:           "list_invoices",
			RawInputSchema: json.RawMessage(`{"type":"object","properties":{"org":{"type":"string"},"page":{"type":"integer"}},"required":["org"]}`),
		}

		Set{"org": "12345"}.RewriteTool(&tool)

		assertJSONEqual(t, string(tool.RawInputSchema), `{"type":"object","properties":{"page":{"type":"integer"}}}`)
	})

	t.Run("leaves an unrelated tool untouched", func(t *testing.T) {
		tool := mcp.Tool{
			Name: "ping",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{"query": map[string]any{"type": "string"}},
				Required:   []string{"query"},
			},
		}
		before := tool

		Set{"org": "12345"}.RewriteTool(&tool)

		if !reflect.DeepEqual(tool, before) {
			t.Errorf("tool changed:\ngot:  %#v\nwant: %#v", tool, before)
		}
	})
}

func TestSetRewriteRequestBody(t *testing.T) {
	tests := []struct {
		name     string
		set      Set
		body     string
		expected string
	}{
		{
			name:     "injects into tools/call arguments",
			set:      Set{"headers.X-Account-Id": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"page":2}}}`,
			expected: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"page":2,"headers":{"X-Account-Id":"12345"}}}}`,
		},
		{
			name:     "overwrites a caller-supplied value",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"org":"99999"}}}`,
			expected: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"org":"12345"}}}`,
		},
		{
			name:     "creates arguments when the call has none",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices"}}`,
			expected: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_invoices","arguments":{"org":"12345"}}}`,
		},
		{
			name:     "leaves other methods alone",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			expected: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		},
		{
			name:     "malformed body is returned as-is",
			set:      Set{"org": "12345"},
			body:     `not json`,
			expected: `not json`,
		},
		{
			name:     "empty set is a no-op",
			set:      Set{},
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`,
			expected: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJSONEqual(t, string(tt.set.RewriteRequestBody([]byte(tt.body))), tt.expected)
		})
	}
}

func TestSetRewriteResponseBody(t *testing.T) {
	tests := []struct {
		name     string
		set      Set
		body     string
		expected string
	}{
		{
			name:     "strips the property from every tool",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{"type":"object","properties":{"org":{"type":"string"},"page":{"type":"integer"}},"required":["org","page"]}},{"name":"b","inputSchema":{"type":"object","properties":{"org":{"type":"string"}},"required":["org"]}}]}}`,
			expected: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{"type":"object","properties":{"page":{"type":"integer"}},"required":["page"]}},{"name":"b","inputSchema":{"type":"object","properties":{}}}]}}`,
		},
		{
			name:     "leaves a response with no tool list alone",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`,
			expected: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`,
		},
		{
			name:     "leaves an error response alone",
			set:      Set{"org": "12345"},
			body:     `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`,
			expected: `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`,
		},
		{
			name:     "malformed body is returned as-is",
			set:      Set{"org": "12345"},
			body:     `not json`,
			expected: `not json`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJSONEqual(t, string(tt.set.RewriteResponseBody([]byte(tt.body))), tt.expected)
		})
	}
}

// assertJSONEqual compares two payloads by structure, so key ordering does not
// decide the test. Non-JSON inputs are compared verbatim.
func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()

	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		if got != want {
			t.Errorf("got:  %s\nwant: %s", got, want)
		}
		return
	}
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("result is not valid JSON: %s", got)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}
