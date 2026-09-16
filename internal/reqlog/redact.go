package reqlog

import (
	"bytes"
	"encoding/json"
)

// Only these params survive redaction. Anything else a message carries is
// dropped rather than risk logging content nobody reviewed.
var keptParams = []string{"name", "uri", "cursor", "protocolVersion", "clientInfo", "capabilities", "_meta", "level", "ref"}

// RedactedRPCBody re-encodes a JSON-RPC message, or a batch of them, for the
// request_body log attribute, which the log store parses for its RpcMethod and
// RpcTool columns. Argument values become their JSON type and results are
// dropped, because values carry query text and customer data. ok is false when
// body is not JSON-RPC.
func RedactedRPCBody(body []byte) (string, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return "", false
		}
		out := make([]map[string]any, 0, len(batch))
		for _, raw := range batch {
			msg, ok := redactMessage(raw)
			if !ok {
				return "", false
			}
			out = append(out, msg)
		}
		return encode(out)
	}

	msg, ok := redactMessage(trimmed)
	if !ok {
		return "", false
	}
	return encode(msg)
}

func redactMessage(raw json.RawMessage) (map[string]any, bool) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, false
	}
	if _, ok := msg["jsonrpc"]; !ok {
		return nil, false
	}

	out := map[string]any{}
	for _, key := range []string{"jsonrpc", "id", "method"} {
		if value, ok := msg[key]; ok {
			out[key] = value
		}
	}
	if params, ok := msg["params"]; ok {
		out["params"] = redactParams(params)
	}
	if _, ok := msg["result"]; ok {
		out["result"] = "[redacted]"
	}
	if errObj, ok := msg["error"]; ok {
		var e struct {
			Code int `json:"code"`
		}
		_ = json.Unmarshal(errObj, &e)
		out["error"] = map[string]any{"code": e.Code}
	}
	return out, true
}

func redactParams(raw json.RawMessage) any {
	var params map[string]json.RawMessage
	if err := json.Unmarshal(raw, &params); err != nil {
		return "[redacted]"
	}

	out := map[string]any{}
	for _, key := range keptParams {
		if value, ok := params[key]; ok {
			out[key] = value
		}
	}
	if args, ok := params["arguments"]; ok {
		out["arguments"] = argumentTypes(args)
	}
	if arg, ok := params["argument"]; ok {
		var completion struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(arg, &completion)
		out["argument"] = map[string]any{"name": completion.Name, "value": "[redacted]"}
	}
	return out
}

func argumentTypes(raw json.RawMessage) any {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return "[" + jsonType(raw) + "]"
	}
	out := make(map[string]string, len(args))
	for name, value := range args {
		out[name] = "[" + jsonType(value) + "]"
	}
	return out
}

func jsonType(value json.RawMessage) string {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		return "empty"
	}
	switch trimmed[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

func encode(v any) (string, bool) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}
