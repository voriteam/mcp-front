package pinnedargs

import (
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
)

// RewriteRequestBody sets the pinned values on a tools/call request body. A
// body that is not a tools/call request, or is not valid JSON, is returned
// unchanged.
func (s Set) RewriteRequestBody(body []byte) []byte {
	if len(s) == 0 {
		return body
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil {
		return body
	}
	var method string
	if err := json.Unmarshal(message["method"], &method); err != nil || method != "tools/call" {
		return body
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(message["params"], &params); err != nil {
		params = map[string]json.RawMessage{}
	}
	arguments, err := json.Marshal(s.Apply(json.RawMessage(params["arguments"])))
	if err != nil {
		return body
	}
	params["arguments"] = arguments

	return remarshal(message, "params", params, body)
}

// RewriteResponseBody strips the pinned properties from the tool schemas in a
// tools/list response body. A body carrying no tool list, or invalid JSON, is
// returned unchanged.
func (s Set) RewriteResponseBody(body []byte) []byte {
	if len(s) == 0 {
		return body
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil {
		return body
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(message["result"], &result); err != nil {
		return body
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil {
		return body
	}

	for _, tool := range tools {
		tool["inputSchema"] = json.RawMessage(s.RewriteRawSchema(tool["inputSchema"]))
	}
	rewritten, err := json.Marshal(tools)
	if err != nil {
		return body
	}
	result["tools"] = rewritten

	return remarshal(message, "result", result, body)
}

func remarshal(message map[string]json.RawMessage, key string, value any, body []byte) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return body
	}
	message[key] = encoded
	rewritten, err := json.Marshal(message)
	if err != nil {
		return body
	}
	return rewritten
}

// RewriteTools strips the pinned properties from a discovered tool list,
// rewriting the tools in place.
func (s Set) RewriteTools(tools []mcp.Tool) []mcp.Tool {
	if len(s) == 0 {
		return tools
	}
	for i := range tools {
		s.RewriteTool(&tools[i])
	}
	return tools
}
