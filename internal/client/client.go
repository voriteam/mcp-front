package client

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/log"
)

// MCPClientInterface is the interface we need from mcp-go client
type MCPClientInterface interface {
	Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error)
	ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error)
	CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
	ListPrompts(ctx context.Context, request mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error)
	GetPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)
	ListResources(ctx context.Context, request mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error)
	ReadResource(ctx context.Context, request mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error)
	ListResourceTemplates(ctx context.Context, request mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error)
	Ping(ctx context.Context) error
	Start(ctx context.Context) error
	Close() error
}

// TransportCreator creates the underlying MCP transport client
type TransportCreator func(conf *config.MCPClientConfig) (MCPClientInterface, error)

// DefaultTransportCreator creates the appropriate MCP transport based on config
func DefaultTransportCreator(conf *config.MCPClientConfig) (MCPClientInterface, error) {
	if conf.Command != "" || conf.TransportType == config.MCPClientTypeStdio {
		if conf.Command == "" {
			return nil, errors.New("command is required for stdio transport")
		}

		envs := make([]string, 0, len(conf.Env))
		for k, v := range conf.Env {
			envs = append(envs, fmt.Sprintf("%s=%s", k, v))
		}

		log.LogInfoWithFields("client", "Starting stdio MCP process", map[string]any{
			"command": conf.Command,
			"args":    conf.Args,
			"env":     envs,
		})

		mcpClient, err := client.NewStdioMCPClient(conf.Command, envs, conf.Args...)
		if err != nil {
			log.LogErrorWithFields("client", "Failed to start stdio MCP process", map[string]any{
				"command": conf.Command,
				"args":    conf.Args,
				"error":   err.Error(),
			})
			return nil, err
		}

		log.LogInfoWithFields("client", "Successfully started stdio MCP process", map[string]any{
			"command": conf.Command,
		})

		return mcpClient, nil
	}

	if conf.URL != "" {
		if conf.TransportType == config.MCPClientTypeStreamable {
			var options []transport.StreamableHTTPCOption
			if len(conf.Headers) > 0 {
				options = append(options, transport.WithHTTPHeaders(conf.Headers))
			}
			// mcp-go always serializes an empty "params":{} object on requests
			// and notifications. Strict MCP servers (e.g. Materialize) reject
			// it with HTTP 422; an empty params is equivalent to an absent one
			// per JSON-RPC 2.0, so a transport that strips it is safe for every
			// backend and keeps mcp-front compatible with strict servers.
			httpClient := &http.Client{Transport: gzipGuardTransport{base: stripEmptyParamsTransport{base: http.DefaultTransport}}}
			if conf.Timeout > 0 {
				httpClient.Timeout = conf.Timeout
			}
			options = append(options, transport.WithHTTPBasicClient(httpClient))
			mcpClient, err := client.NewStreamableHttpClient(conf.URL, options...)
			if err != nil {
				return nil, err
			}
			return mcpClient, nil
		} else {
			var options []transport.ClientOption
			if len(conf.Headers) > 0 {
				options = append(options, client.WithHeaders(conf.Headers))
			}
			mcpClient, err := client.NewSSEMCPClient(conf.URL, options...)
			if err != nil {
				return nil, err
			}
			return mcpClient, nil
		}
	}

	return nil, errors.New("invalid client type: must have either command or url")
}

// stripEmptyParamsTransport is an http.RoundTripper that removes an empty
// "params":{} (or null) value from outgoing JSON-RPC request bodies. mcp-go
// always serializes that empty object, but JSON-RPC 2.0 treats empty params as
// identical to absent params, and strict MCP servers (e.g. Materialize) reject
// the empty object with HTTP 422. Stripping it is safe for every server.
type stripEmptyParamsTransport struct {
	base http.RoundTripper
}

func (t stripEmptyParamsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Body == nil || req.Method != http.MethodPost {
		return base.RoundTrip(req)
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	body = stripEmptyJSONRPCParams(body)

	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return base.RoundTrip(clone)
}

// stripEmptyJSONRPCParams removes a top-level "params" key from a JSON-RPC
// message body when its value is an empty object or null. Bodies that are not
// a JSON object, or whose params carries content, are returned unchanged.
func stripEmptyJSONRPCParams(body []byte) []byte {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return body
	}
	params, ok := fields["params"]
	if !ok {
		return body
	}
	switch string(bytes.TrimSpace(params)) {
	case "{}", "null":
		delete(fields, "params")
		if out, err := json.Marshal(fields); err == nil {
			return out
		}
	}
	return body
}

// gzipGuardTransport is an http.RoundTripper that guarantees gzip bytes never
// reach the JSON decoder in mcp-go's streamable HTTP client. Some backends
// (gke, datadog) intermittently deliver bodies that are still gzip-compressed
// when decoded — either Go's transparent decompression was skipped or the
// backend double-encoded; the trigger is unknown. If a response still carries
// Content-Encoding: gzip, or an application/json body starts with the gzip
// magic bytes, the body is wrapped in a gzip reader (repeatedly, for
// double-encoded bodies) and a WARN is logged with the response details so
// production occurrences identify the true cause. SSE responses pass through
// untouched.
type gzipGuardTransport struct {
	base http.RoundTripper
}

// maxGzipDepth bounds nested decompression of double-encoded bodies.
const maxGzipDepth = 5

func (t gzipGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "text/event-stream") {
		return resp, nil
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	headerGzip := strings.EqualFold(contentEncoding, "gzip")
	sniffJSON := strings.Contains(contentType, "application/json")
	if !headerGzip && !sniffJSON {
		return resp, nil
	}

	br := bufio.NewReader(resp.Body)
	body := &gzipGuardBody{r: br, closers: []io.Closer{resp.Body}}
	magic := hasGzipMagic(br)

	trigger := ""
	if headerGzip {
		trigger = "header"
	} else if magic {
		trigger = "magic-bytes"
	}
	if trigger == "" {
		resp.Body = body
		return resp, nil
	}

	fields := map[string]any{
		"host":            req.URL.Host,
		"method":          req.Method,
		"acceptEncoding":  req.Header.Get("Accept-Encoding"),
		"status":          resp.StatusCode,
		"proto":           resp.Proto,
		"contentEncoding": contentEncoding,
		"contentType":     resp.Header.Get("Content-Type"),
		"contentLength":   resp.Header.Get("Content-Length"),
		"trigger":         trigger,
	}

	if !magic {
		log.LogWarnWithFields("client", "Response claims gzip encoding but body lacks gzip magic bytes, passing through", fields)
		resp.Body = body
		return resp, nil
	}

	depth := 0
	for depth < maxGzipDepth && hasGzipMagic(br) {
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			fields["error"] = gzErr.Error()
			fields["depth"] = depth
			log.LogWarnWithFields("client", "Failed to decompress gzip response body", fields)
			break
		}
		body.closers = append(body.closers, gz)
		br = bufio.NewReader(gz)
		depth++
	}
	body.r = br

	if depth == 0 {
		resp.Body = body
		return resp, nil
	}

	fields["depth"] = depth
	log.LogWarnWithFields("client", "Decompressed gzip response body that would have reached the JSON decoder", fields)

	resp.Body = body
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return resp, nil
}

func hasGzipMagic(br *bufio.Reader) bool {
	b, err := br.Peek(2)
	return err == nil && b[0] == 0x1f && b[1] == 0x8b
}

// gzipGuardBody chains the buffered/decompressed reader with every closer in
// the decompression stack. Close releases gzip readers innermost-first, then
// the original body, so the HTTP connection can be reused.
type gzipGuardBody struct {
	r       io.Reader
	closers []io.Closer
}

func (b *gzipGuardBody) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *gzipGuardBody) Close() error {
	var firstErr error
	for i := len(b.closers) - 1; i >= 0; i-- {
		if err := b.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
