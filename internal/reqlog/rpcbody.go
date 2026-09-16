package reqlog

import (
	"bytes"
	"encoding/json"
)

// RPCBody returns a JSON-RPC message, or a batch of them, compacted onto one
// line for the request_body log attribute, which the log store parses for its
// RpcMethod and RpcTool columns. ok is false for anything that is not JSON-RPC,
// so other JSON endpoints such as client registration are never logged.
func RPCBody(body []byte) (string, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
			return "", false
		}
		for _, msg := range batch {
			if !isRPCMessage(msg) {
				return "", false
			}
		}
	} else if !isRPCMessage(trimmed) {
		return "", false
	}

	var compacted bytes.Buffer
	if err := json.Compact(&compacted, trimmed); err != nil {
		return "", false
	}
	return compacted.String(), true
}

func isRPCMessage(raw json.RawMessage) bool {
	var msg struct {
		JSONRPC string `json:"jsonrpc"`
	}
	return json.Unmarshal(raw, &msg) == nil && msg.JSONRPC != ""
}
