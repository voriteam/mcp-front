package reqlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactedRPCBodyKeepsTheEnvelopeAndArgumentTypes(t *testing.T) {
	body, ok := RedactedRPCBody([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"postgres__execute_sql","arguments":{"sql":"select * from customers","limit":5,"dry":true,"tags":["a"],"opts":{"x":1},"none":null},"_meta":{"progressToken":1}}}`))

	require.True(t, ok)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"postgres__execute_sql","arguments":{"sql":"[string]","limit":"[number]","dry":"[boolean]","tags":"[array]","opts":"[object]","none":"[null]"},"_meta":{"progressToken":1}}}`, body)
}

func TestRedactedRPCBodyDropsUnlistedParamsAndResults(t *testing.T) {
	body, ok := RedactedRPCBody([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"model output"},"params":{"messages":["private"]}}`))

	require.True(t, ok)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":"[redacted]","params":{}}`, body)
}

func TestRedactedRPCBodyRedactsCompletionValues(t *testing.T) {
	body, ok := RedactedRPCBody([]byte(`{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q","value":"half-typed secret"}}}`))

	require.True(t, ok)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q","value":"[redacted]"}}}`, body)
}

func TestRedactedRPCBodyKeepsOnlyTheErrorCode(t *testing.T) {
	body, ok := RedactedRPCBody([]byte(`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"user said something"}}`))

	require.True(t, ok)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":3,"error":{"code":-32000}}`, body)
}

func TestRedactedRPCBodyHandlesBatches(t *testing.T) {
	body, ok := RedactedRPCBody([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`))

	require.True(t, ok)
	assert.JSONEq(t, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`, body)
}

func TestRedactedRPCBodyRejectsOtherJSON(t *testing.T) {
	_, ok := RedactedRPCBody([]byte(`{"client_name":"x","redirect_uris":["https://a"]}`))
	assert.False(t, ok)

	_, ok = RedactedRPCBody([]byte(`not json`))
	assert.False(t, ok)
}
