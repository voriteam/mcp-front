package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/stainless-api/mcp-front/internal/reqlog"
)

// Bodies above this are passed through without envelope fields rather than
// parsed from a truncated prefix.
const maxInspectedBodyBytes = 1 << 20

const maxLoggedErrorBytes = 256

// rpcRequest names the envelope fields lifted into their own attributes. The
// whole message, arguments included, is logged separately as request_body.
type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name            string          `json:"name"`
		Arguments       json.RawMessage `json:"arguments"`
		URI             string          `json:"uri"`
		ProtocolVersion string          `json:"protocolVersion"`
		ClientInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	} `json:"params"`
}

// peekJSONBody returns the body of a JSON POST, or nil for any other request,
// and swaps r.Body for one that replays what was read. complete is false when
// the body exceeded maxInspectedBodyBytes.
func peekJSONBody(r *http.Request) (body []byte, complete bool) {
	if r.Method != http.MethodPost || r.Body == nil || r.Body == http.NoBody {
		return nil, false
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, false
	}

	original := r.Body
	body, _ = io.ReadAll(io.LimitReader(original, maxInspectedBodyBytes+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), original), original}

	return body, len(body) <= maxInspectedBodyBytes
}

func rpcFields(body []byte) map[string]any {
	fields := map[string]any{}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []rpcRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			fields["jsonrpc.parse_error"] = true
			return fields
		}
		methods := make([]string, 0, len(batch))
		for _, req := range batch {
			methods = append(methods, req.Method)
		}
		fields["jsonrpc.batch.size"] = len(batch)
		fields["mcp.method.name"] = strings.Join(methods, ",")
		return fields
	}

	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		fields["jsonrpc.parse_error"] = true
		return fields
	}

	if req.Method != "" {
		fields["mcp.method.name"] = req.Method
	}
	if id := requestID(req.ID); id != "" {
		fields["jsonrpc.request.id"] = id
	}

	switch req.Method {
	case "tools/call":
		setIfPresent(fields, "gen_ai.tool.name", req.Params.Name)
		setIfPresent(fields, "mcp.tool.argument_names", argumentNames(req.Params.Arguments))
	case "prompts/get":
		setIfPresent(fields, "gen_ai.prompt.name", req.Params.Name)
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		setIfPresent(fields, "mcp.resource.uri", req.Params.URI)
	case "initialize":
		setIfPresent(fields, "mcp.protocol.version", req.Params.ProtocolVersion)
		setIfPresent(fields, "mcp.client.name", req.Params.ClientInfo.Name)
		setIfPresent(fields, "mcp.client.version", req.Params.ClientInfo.Version)
	}

	return fields
}

func requestID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var id any
	if err := json.Unmarshal(raw, &id); err != nil || id == nil {
		return ""
	}
	switch v := id.(type) {
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return fmt.Sprint(v)
	}
}

func argumentNames(raw json.RawMessage) string {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return ""
	}
	return strings.Join(slices.Sorted(maps.Keys(args)), ",")
}

func canonicalMessage(fields map[string]any, r *http.Request, status int, duration time.Duration, errorMessage string) string {
	label := r.Method + " " + r.URL.Path
	if method, ok := fields["mcp.method.name"].(string); ok {
		label = method
		if tool, ok := fields["gen_ai.tool.name"].(string); ok {
			label += " " + tool
		}
	}

	msg := fmt.Sprintf("[CANONICAL-REQUEST-LOG] %s %d in %s", label, status, reqlog.FormatDuration(duration))
	if errorMessage != "" {
		msg += ": " + errorMessage
	}
	return msg
}

// errorText prefers the message inside a JSON-RPC error response over the raw
// JSON, which is what the SSE transport sends with its 4xx replies.
func errorText(body []byte) string {
	var rpc struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err == nil && rpc.Error.Message != "" {
		return rpc.Error.Message
	}
	return strings.TrimSpace(string(body))
}

func setIfPresent(fields map[string]any, key, value string) {
	if value != "" {
		fields[key] = value
	}
}
