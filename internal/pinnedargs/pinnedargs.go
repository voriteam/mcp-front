// Package pinnedargs applies a server's fixed tool-call arguments: it strips
// the pinned properties from advertised tool schemas and sets their values on
// outbound tool calls.
package pinnedargs

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// Set maps a dotted argument path to the value pinned at that path.
type Set map[string]string

// SplitPath splits a dotted argument path into its segments. A dot separates
// segments; `\.` is a literal dot in a property name and `\\` a literal
// backslash. A trailing lone backslash is kept verbatim.
func SplitPath(path string) []string {
	segments := []string{}
	var seg strings.Builder
	for i := 0; i < len(path); i++ {
		switch c := path[i]; {
		case c == '\\' && i+1 < len(path) && (path[i+1] == '.' || path[i+1] == '\\'):
			seg.WriteByte(path[i+1])
			i++
		case c == '.':
			segments = append(segments, seg.String())
			seg.Reset()
		default:
			seg.WriteByte(c)
		}
	}
	return append(segments, seg.String())
}

// Apply returns the arguments with every pinned path set to its value,
// creating intermediate objects as needed. A caller-supplied value at a pinned
// path is replaced. args may be nil, a map, or JSON that decodes to an object;
// anything else is discarded, since a tool whose arguments are pinned takes an
// object.
func (s Set) Apply(args any) map[string]any {
	out := toMap(args)
	for _, path := range slices.Sorted(maps.Keys(s)) {
		setPath(out, SplitPath(path), s[path])
	}
	return out
}

func toMap(args any) map[string]any {
	switch v := args.(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return v
	case json.RawMessage:
		return decodeMap(v)
	case []byte:
		return decodeMap(v)
	case string:
		return decodeMap([]byte(v))
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return map[string]any{}
		}
		return decodeMap(raw)
	}
}

func decodeMap(raw []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func setPath(obj map[string]any, segments []string, value string) {
	for _, seg := range segments[:len(segments)-1] {
		child, ok := obj[seg].(map[string]any)
		if !ok {
			child = map[string]any{}
			obj[seg] = child
		}
		obj = child
	}
	obj[segments[len(segments)-1]] = value
}

// RewriteTool removes every pinned property from the tool's input schema, so
// the model neither sees the property nor can be faulted for omitting it.
func (s Set) RewriteTool(tool *mcp.Tool) {
	if len(s) == 0 {
		return
	}
	if len(tool.RawInputSchema) > 0 {
		tool.RawInputSchema = s.RewriteRawSchema(tool.RawInputSchema)
		return
	}
	if tool.InputSchema.Properties == nil {
		return
	}
	schema := map[string]any{"properties": tool.InputSchema.Properties}
	if len(tool.InputSchema.Required) > 0 {
		schema["required"] = toAnySlice(tool.InputSchema.Required)
	}
	s.stripSchema(schema)

	tool.InputSchema.Properties, _ = schema["properties"].(map[string]any)
	tool.InputSchema.Required = toStringSlice(schema["required"])
}

// RewriteRawSchema removes every pinned property from a raw JSON Schema. Input
// that is not a JSON object, or a schema that does not declare the pinned
// path, is returned unchanged.
func (s Set) RewriteRawSchema(raw json.RawMessage) json.RawMessage {
	if len(s) == 0 || len(raw) == 0 {
		return raw
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return raw
	}
	if !s.stripSchema(schema) {
		return raw
	}
	rewritten, err := json.Marshal(schema)
	if err != nil {
		return raw
	}
	return rewritten
}

// stripSchema deletes each pinned path from schema, reporting whether anything
// changed.
func (s Set) stripSchema(schema map[string]any) bool {
	changed := false
	for _, path := range slices.Sorted(maps.Keys(s)) {
		if stripPath(schema, SplitPath(path)) {
			changed = true
		}
	}
	return changed
}

// stripPath removes one property from schema and from its object's required
// list, then prunes any ancestor object left with no properties — otherwise the
// caller would still have to send an empty object.
func stripPath(schema map[string]any, segments []string) bool {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return false
	}
	name := segments[0]
	if len(segments) > 1 {
		child, ok := props[name].(map[string]any)
		if !ok || !stripPath(child, segments[1:]) {
			return false
		}
		if childProps, ok := child["properties"].(map[string]any); !ok || len(childProps) > 0 {
			return true
		}
	} else if _, ok := props[name]; !ok {
		return false
	}

	delete(props, name)
	if required := toStringSlice(schema["required"]); len(required) > 0 {
		remaining := slices.DeleteFunc(required, func(r string) bool { return r == name })
		if len(remaining) == 0 {
			delete(schema, "required")
		} else {
			schema["required"] = toAnySlice(remaining)
		}
	}
	return true
}

func toAnySlice(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// toStringSlice reads a JSON Schema `required` list, which survives a
// round-trip through map[string]any as []any.
func toStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
