package reqlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCBodyKeepsTheWholeMessage(t *testing.T) {
	body, ok := RPCBody([]byte(`{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": {"name": "postgres__execute_sql", "arguments": {"sql": "select * from customers"}}
	}`))

	require.True(t, ok)
	assert.Equal(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"postgres__execute_sql","arguments":{"sql":"select * from customers"}}}`, body)
}

func TestRPCBodyAcceptsBatches(t *testing.T) {
	body, ok := RPCBody([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}, {"jsonrpc":"2.0","method":"notifications/initialized"}]`))

	require.True(t, ok)
	assert.Equal(t, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`, body)
}

func TestRPCBodyRejectsOtherJSON(t *testing.T) {
	for _, body := range []string{
		`{"client_name":"x","redirect_uris":["https://a"]}`,
		`[{"jsonrpc":"2.0","method":"ping"},{"not":"rpc"}]`,
		`[]`,
		`not json`,
	} {
		_, ok := RPCBody([]byte(body))
		assert.False(t, ok, body)
	}
}
