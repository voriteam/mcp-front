package aggregate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamlineDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short description unchanged",
			input:    "Execute a SQL query",
			expected: "Execute a SQL query",
		},
		{
			name:     "strips examples block",
			input:    "Search for issues.\n\n<examples>\n### Find bugs\nsearch_issues(query='bugs')\n</examples>\n\nReturns results.",
			expected: "Search for issues.\n\nReturns results.",
		},
		{
			name:     "strips hints block",
			input:    "Get issue details.\n\n<hints>\n- Use issueUrl parameter\n- Extract from URL\n</hints>",
			expected: "Get issue details.",
		},
		{
			name:     "strips multiple blocks",
			input:    "Tool description.\n\n<examples>\nfoo\n</examples>\n\nMiddle text.\n\n<hints>\nbar\n</hints>",
			expected: "Tool description.\n\nMiddle text.",
		},
		{
			name:     "truncates long description at sentence boundary",
			input:    "This is a tool that does many things. It supports complex queries with boolean operators. It also handles pagination and filtering. " + "Additional details that push it well beyond the maximum allowed description length for streamlined responses in the gateway multiplexer endpoint. More text here to ensure truncation happens correctly at a sentence boundary.",
			expected: "This is a tool that does many things. It supports complex queries with boolean operators. It also handles pagination and filtering. Additional details that push it well beyond the maximum allowed description length for streamlined responses in the gateway multiplexer endpoint.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, streamlineDescription(tt.input))
		})
	}
}

func TestStreamlinePropertyDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single sentence unchanged",
			input:    "The SQL query to execute.",
			expected: "The SQL query to execute.",
		},
		{
			name:     "keeps only the first sentence",
			input:    "Due date (ISO format). On update, pass null to remove the due date",
			expected: "Due date (ISO format).",
		},
		{
			name:     "abbreviations do not end a sentence",
			input:    "Parent issue ID or identifier (e.g., LIN-123). Null to remove",
			expected: "Parent issue ID or identifier (e.g., LIN-123).",
		},
		{
			name:     "parenthesised abbreviations do not end a sentence",
			input:    "Label names (e.g. [\"Bug\"]) to add. Append-only; existing labels are never removed",
			expected: "Label names (e.g. [\"Bug\"]) to add.",
		},
		{
			name:     "decimals and URLs are not boundaries",
			input:    "Timeout in seconds, default 2.5 (see https://example.com/docs). Must be positive",
			expected: "Timeout in seconds, default 2.5 (see https://example.com/docs).",
		},
		{
			name:     "line break ends the sentence",
			input:    "Filter by status:\n- open\n- closed",
			expected: "Filter by status:",
		},
		{
			name:     "long first sentence is cut at a word boundary",
			input:    strings.Repeat("word ", 40) + "end.",
			expected: strings.TrimSpace(strings.Repeat("word ", 30)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, streamlinePropertyDescription(tt.input))
		})
	}
}

func parseSchema(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(raw, &parsed))
	return parsed
}

func properties(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "schema has no properties: %v", schema)
	return props
}

func TestStreamlineInputSchema(t *testing.T) {
	t.Run("shortens property descriptions to their first sentence", func(t *testing.T) {
		result := streamlineInputSchema(json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "The SQL query to execute against the database. Must be a single statement."
				},
				"limit": {
					"type": "integer",
					"default": 50,
					"description": "Maximum number of rows to return"
				}
			},
			"required": ["query"]
		}`))

		parsed := parseSchema(t, result)
		props := properties(t, parsed)
		assert.Equal(t, map[string]any{"type": "string", "description": "The SQL query to execute against the database."}, props["query"])
		assert.Equal(t, map[string]any{"type": "integer", "default": float64(50), "description": "Maximum number of rows to return"}, props["limit"])
		assert.Equal(t, []any{"query"}, parsed["required"])
	})

	t.Run("collapses nullable anyOf and keeps the outer description", func(t *testing.T) {
		result := streamlineInputSchema(json.RawMessage(`{
			"type": "object",
			"properties": {
				"region": {
					"anyOf": [
						{"type": "string", "format": "uri", "description": "The region URL"},
						{"type": "null"}
					],
					"default": null,
					"description": "Optional region parameter. Defaults to the caller's region"
				}
			}
		}`))

		region := properties(t, parseSchema(t, result))["region"]
		assert.Equal(t, map[string]any{
			"type":        "string",
			"format":      "uri",
			"default":     nil,
			"description": "Optional region parameter.",
		}, region)
	})

	t.Run("applies the same rules inside nested objects, items, $defs and oneOf", func(t *testing.T) {
		result := streamlineInputSchema(json.RawMessage(`{
			"type": "object",
			"$defs": {
				"Filter": {
					"type": "object",
					"additionalProperties": false,
					"properties": {
						"field": {"type": "string", "pattern": "^[a-z]+$", "description": "Field to filter on. Must be indexed."}
					}
				}
			},
			"properties": {
				"filters": {"type": "array", "items": {"$ref": "#/$defs/Filter"}, "minItems": 1},
				"telemetry": {
					"type": "object",
					"properties": {
						"intent": {"type": "string", "minLength": 1, "description": "Briefly describe the wider context task. Keep it short."}
					},
					"required": ["intent"]
				},
				"patch": {
					"type": "array",
					"items": {
						"oneOf": [
							{"type": "object", "properties": {"op": {"const": "replace"}, "old": {"type": "string", "minLength": 1, "description": "Exact text to replace. Must match once."}}},
							{"type": "object", "properties": {"op": {"const": "append"}, "text": {"type": "string", "maxLength": 100}}}
						]
					}
				}
			}
		}`))

		parsed := parseSchema(t, result)
		field := properties(t, parsed["$defs"].(map[string]any)["Filter"].(map[string]any))["field"]
		assert.Equal(t, map[string]any{"type": "string", "description": "Field to filter on."}, field)
		assert.NotContains(t, parsed["$defs"].(map[string]any)["Filter"], "additionalProperties")

		props := properties(t, parsed)
		assert.Equal(t, map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/Filter"}}, props["filters"])

		telemetry := props["telemetry"].(map[string]any)
		assert.Equal(t, map[string]any{"type": "string", "description": "Briefly describe the wider context task."}, properties(t, telemetry)["intent"])
		assert.Equal(t, []any{"intent"}, telemetry["required"])

		ops := props["patch"].(map[string]any)["items"].(map[string]any)["oneOf"].([]any)
		assert.Equal(t, map[string]any{"type": "string", "description": "Exact text to replace."}, properties(t, ops[0].(map[string]any))["old"])
		assert.Equal(t, map[string]any{"type": "string"}, properties(t, ops[1].(map[string]any))["text"])
	})

	t.Run("keeps format, enum and default, drops bounds, pattern, additionalProperties and extensions", func(t *testing.T) {
		result := streamlineInputSchema(json.RawMessage(`{
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"limit": {
					"type": "number",
					"minimum": 1,
					"maximum": 100,
					"exclusiveMaximum": 101,
					"default": 10
				},
				"query": {
					"type": "string",
					"minLength": 2,
					"maxLength": 200,
					"pattern": "^[a-z]+$",
					"format": "uri"
				},
				"output": {
					"type": "string",
					"enum": ["TABLE", "WIDE", "YAML"],
					"x-google-enum-descriptions": ["Table format", "Wide format", "YAML format"]
				}
			}
		}`))

		parsed := parseSchema(t, result)
		assert.NotContains(t, parsed, "additionalProperties")
		props := properties(t, parsed)
		assert.Equal(t, map[string]any{"type": "number", "default": float64(10)}, props["limit"])
		assert.Equal(t, map[string]any{"type": "string", "format": "uri"}, props["query"])
		assert.Equal(t, map[string]any{"type": "string", "enum": []any{"TABLE", "WIDE", "YAML"}}, props["output"])
	})

	t.Run("returns input unchanged on invalid JSON", func(t *testing.T) {
		input := json.RawMessage(`not valid json`)
		assert.Equal(t, input, streamlineInputSchema(input))
	})

	t.Run("returns empty input unchanged", func(t *testing.T) {
		assert.Nil(t, streamlineInputSchema(nil))
	})
}
