package client

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestStripEmptyJSONRPCParams(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty params object is removed",
			in:   `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			want: `{"id":1,"jsonrpc":"2.0","method":"tools/list"}`,
		},
		{
			name: "null params is removed",
			in:   `{"jsonrpc":"2.0","method":"notifications/initialized","params":null}`,
			want: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		},
		{
			name: "absent params is left alone",
			in:   `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			want: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		},
		{
			name: "non-empty params is left alone",
			in:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`,
			want: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`,
		},
		{
			name: "non-JSON body is left alone",
			in:   `not json at all`,
			want: `not json at all`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := string(stripEmptyJSONRPCParams([]byte(c.in)))
			if got != c.want {
				t.Errorf("stripEmptyJSONRPCParams() = %s, want %s", got, c.want)
			}
		})
	}
}

// captureRoundTripper records the request body it receives.
type captureRoundTripper struct{ body []byte }

func (c *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		c.body, _ = io.ReadAll(req.Body)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     make(http.Header),
	}, nil
}

func TestStripEmptyParamsTransport(t *testing.T) {
	capture := &captureRoundTripper{}
	rt := stripEmptyParamsTransport{base: capture}

	req, err := http.NewRequest(
		http.MethodPost, "http://example.com/mcp",
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	want := `{"id":1,"jsonrpc":"2.0","method":"tools/list"}`
	if string(capture.body) != want {
		t.Errorf("forwarded body = %s, want %s", capture.body, want)
	}
}
