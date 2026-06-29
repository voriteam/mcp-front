package client

import (
	"bytes"
	"compress/gzip"
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

// staticResponseRoundTripper returns a fixed response for any request.
type staticResponseRoundTripper struct{ resp *http.Response }

func (s *staticResponseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return s.resp, nil
}

// closeTrackingReadCloser records whether Close was called.
type closeTrackingReadCloser struct {
	io.Reader
	closed bool
}

func (c *closeTrackingReadCloser) Close() error {
	c.closed = true
	return nil
}

func gzipCompress(t *testing.T, data []byte, times int) []byte {
	t.Helper()
	for range times {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
	}
	return data
}

func gzipGuardRoundTrip(t *testing.T, headers map[string]string, body io.ReadCloser) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/2.0",
		Header:     make(http.Header),
		Body:       body,
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	rt := gzipGuardTransport{base: &staticResponseRoundTripper{resp: resp}}
	req, err := http.NewRequest(http.MethodPost, "http://backend.example/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestGzipGuardTransport(t *testing.T) {
	plain := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)

	t.Run("plain JSON passes through untouched", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json"},
			io.NopCloser(bytes.NewReader(plain)),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("body = %s, want %s", got, plain)
		}
	})

	t.Run("gzip body with Content-Encoding header is decompressed", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"},
			io.NopCloser(bytes.NewReader(gzipCompress(t, plain, 1))),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("body = %s, want %s", got, plain)
		}
		if resp.Header.Get("Content-Encoding") != "" {
			t.Errorf("Content-Encoding not cleared: %s", resp.Header.Get("Content-Encoding"))
		}
		if resp.ContentLength != -1 {
			t.Errorf("ContentLength = %d, want -1", resp.ContentLength)
		}
	})

	t.Run("gzip body without Content-Encoding header is sniffed and decompressed", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json"},
			io.NopCloser(bytes.NewReader(gzipCompress(t, plain, 1))),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("body = %s, want %s", got, plain)
		}
	})

	t.Run("double-gzipped body is fully decompressed", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"},
			io.NopCloser(bytes.NewReader(gzipCompress(t, plain, 2))),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("body = %s, want %s", got, plain)
		}
	})

	t.Run("SSE response passes through untouched", func(t *testing.T) {
		body := io.NopCloser(bytes.NewReader([]byte("event: message\ndata: {}\n\n")))
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "text/event-stream"},
			body,
		)
		if resp.Body != body {
			t.Error("SSE body was wrapped, want original reader")
		}
	})

	t.Run("empty body does not panic", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json"},
			io.NopCloser(bytes.NewReader(nil)),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("body = %q, want empty", got)
		}
	})

	t.Run("close propagates to original body", func(t *testing.T) {
		tracker := &closeTrackingReadCloser{Reader: bytes.NewReader(gzipCompress(t, plain, 1))}
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"},
			tracker,
		)
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if !tracker.closed {
			t.Error("original body was not closed")
		}
	})

	t.Run("gzip header without gzip body passes through", func(t *testing.T) {
		resp := gzipGuardRoundTrip(t,
			map[string]string{"Content-Type": "application/json", "Content-Encoding": "gzip"},
			io.NopCloser(bytes.NewReader(plain)),
		)
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("body = %s, want %s", got, plain)
		}
	})
}
