package httputil

import "net/http"

// NewUserAgentTransport wraps base (or http.DefaultTransport) to set User-Agent
// on every outgoing request per RFC 9110 Section 10.1.5.
// Format: mcp-front/1.0 (build; <version>)
func NewUserAgentTransport(version string, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	ua := "mcp-front/1.0"
	if version != "" {
		ua += " (build; " + version + ")"
	}
	return &userAgentTransport{base: base, ua: ua}
}

// NewClient returns an *http.Client with the User-Agent transport applied.
func NewClient(version string) *http.Client {
	return &http.Client{Transport: NewUserAgentTransport(version, nil)}
}

type userAgentTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.ua)
	}
	return t.base.RoundTrip(req)
}
