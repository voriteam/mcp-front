package aggregate

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	maxDescriptionLength         = 300
	maxPropertyDescriptionLength = 150
)

var (
	xmlBlockPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?s)<examples>.*?</examples>`),
		regexp.MustCompile(`(?s)<hints>.*?</hints>`),
		regexp.MustCompile(`(?s)<example>.*?</example>`),
	}
	multipleNewlines = regexp.MustCompile(`\n{3,}`)

	abbreviations = map[string]bool{"e.g": true, "i.e": true, "etc": true, "vs": true}

	// Validation-only keywords: they tell a model nothing about how to fill the argument.
	droppedSchemaKeys = map[string]bool{
		"additionalProperties": true,
		"minimum":              true,
		"maximum":              true,
		"exclusiveMinimum":     true,
		"exclusiveMaximum":     true,
		"minLength":            true,
		"maxLength":            true,
		"minItems":             true,
		"maxItems":             true,
		"pattern":              true,
	}
)

func streamlineTools(tools []mcp.Tool) []mcp.Tool {
	out := make([]mcp.Tool, len(tools))
	for i, tool := range tools {
		out[i] = streamlineTool(tool)
	}
	return out
}

// mcp-go decodes a backend's inputSchema into InputSchema and never sets
// RawInputSchema, so the trimmed schema moves to RawInputSchema and
// InputSchema is zeroed, which Tool.MarshalJSON requires.
func streamlineTool(tool mcp.Tool) mcp.Tool {
	tool.Description = streamlineDescription(tool.Description)
	raw := tool.RawInputSchema
	if raw == nil {
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return tool
		}
		raw = encoded
	}
	tool.RawInputSchema = streamlineInputSchema(raw)
	tool.InputSchema = mcp.ToolInputSchema{}
	return tool
}

func streamlineDescription(desc string) string {
	for _, pat := range xmlBlockPatterns {
		desc = pat.ReplaceAllString(desc, "")
	}
	desc = multipleNewlines.ReplaceAllString(desc, "\n\n")
	return truncate(strings.TrimSpace(desc), maxDescriptionLength)
}

func streamlinePropertyDescription(desc string) string {
	return truncate(firstSentence(strings.TrimSpace(desc)), maxPropertyDescriptionLength)
}

func firstSentence(desc string) string {
	for i := 0; i < len(desc); i++ {
		switch desc[i] {
		case '\n':
			return strings.TrimSpace(desc[:i])
		case '.', '!', '?':
			if i+1 < len(desc) && desc[i+1] != ' ' {
				continue
			}
			word := desc[strings.LastIndexByte(desc[:i], ' ')+1 : i]
			if abbreviations[strings.ToLower(strings.TrimLeft(word, "([\"'"))] {
				continue
			}
			return desc[:i+1]
		}
	}
	return desc
}

func truncate(desc string, limit int) string {
	if len(desc) <= limit {
		return desc
	}
	cut := desc[:limit]
	if i := strings.LastIndex(cut, ". "); i > limit/2 {
		return cut[:i+1]
	}
	if i := strings.LastIndexByte(cut, ' '); i > limit/2 {
		return cut[:i]
	}
	return cut
}

func streamlineInputSchema(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return raw
	}

	streamlineSchema(schema)

	result, err := json.Marshal(schema)
	if err != nil {
		return raw
	}
	return result
}

func streamlineSchema(schema map[string]any) {
	collapseNullable(schema)
	for key, value := range schema {
		switch {
		case droppedSchemaKeys[key] || strings.HasPrefix(key, "x-"):
			delete(schema, key)
		case key == "description":
			if desc, ok := value.(string); ok {
				schema[key] = streamlinePropertyDescription(desc)
			}
		case key == "properties" || key == "$defs":
			if children, ok := value.(map[string]any); ok {
				for _, child := range children {
					streamlineSubschema(child)
				}
			}
		case key == "items" || key == "anyOf" || key == "oneOf" || key == "allOf":
			streamlineSubschema(value)
		}
	}
}

func streamlineSubschema(value any) {
	switch node := value.(type) {
	case map[string]any:
		streamlineSchema(node)
	case []any:
		for _, item := range node {
			streamlineSubschema(item)
		}
	}
}

func collapseNullable(schema map[string]any) {
	anyOf, ok := schema["anyOf"].([]any)
	if !ok || len(anyOf) != 2 {
		return
	}
	var real map[string]any
	hasNull := false
	for _, item := range anyOf {
		branch, ok := item.(map[string]any)
		if !ok {
			return
		}
		if branch["type"] == "null" {
			hasNull = true
		} else {
			real = branch
		}
	}
	if !hasNull || real == nil {
		return
	}
	delete(schema, "anyOf")
	for key, value := range real {
		if _, taken := schema[key]; !taken {
			schema[key] = value
		}
	}
}
