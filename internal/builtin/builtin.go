package builtin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// Handler executes one builtin tool call. userEmail is the authenticated
// mcp-front user the aggregate opened this connection for.
type Handler func(ctx context.Context, userEmail string, args json.RawMessage) (*mcp.CallToolResult, error)

type Tool struct {
	Name         string
	Description  string
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
	Handler      Handler
}

type Client struct {
	serverName string
	userEmail  string
	tools      map[string]Tool
	order      []string
}

func NewClient(serverName, userEmail string, tools []Tool) *Client {
	c := &Client{
		serverName: serverName,
		userEmail:  userEmail,
		tools:      make(map[string]Tool, len(tools)),
		order:      make([]string, 0, len(tools)),
	}
	for _, t := range tools {
		c.tools[t.Name] = t
		c.order = append(c.order, t.Name)
	}
	return c
}

func (c *Client) Start(context.Context) error { return nil }
func (c *Client) Close() error                { return nil }
func (c *Client) Ping(context.Context) error  { return nil }

// The aggregate calls Initialize as a handshake and never inspects capabilities.
func (c *Client) Initialize(context.Context, mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{
		ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		ServerInfo:      mcp.Implementation{Name: c.serverName, Version: "1.0.0"},
	}, nil
}

func (c *Client) ListTools(context.Context, mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	out := make([]mcp.Tool, 0, len(c.order))
	for _, name := range c.order {
		t := c.tools[name]
		out = append(out, mcp.Tool{
			Name:            t.Name,
			Description:     t.Description,
			RawInputSchema:  t.InputSchema,
			RawOutputSchema: t.OutputSchema,
		})
	}
	// Empty NextCursor terminates discoverBackendTools' pagination loop.
	return &mcp.ListToolsResult{Tools: out}, nil
}

func (c *Client) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	t, ok := c.tools[req.Params.Name]
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown tool %q", req.Params.Name)), nil
	}
	// Round-trip through JSON so handlers decode into their own structs
	// regardless of how mcp-go represents Arguments.
	args, err := json.Marshal(req.Params.Arguments)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("decoding arguments: %v", err)), nil
	}
	return t.Handler(ctx, c.userEmail, args)
}

// Unused by the aggregate, which only calls ListTools and CallTool.
func (c *Client) ListPrompts(context.Context, mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	return &mcp.ListPromptsResult{}, nil
}

func (c *Client) GetPrompt(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return nil, fmt.Errorf("builtin %s: prompts not supported", c.serverName)
}

func (c *Client) ListResources(context.Context, mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	return &mcp.ListResourcesResult{}, nil
}

func (c *Client) ReadResource(context.Context, mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return nil, fmt.Errorf("builtin %s: resources not supported", c.serverName)
}

func (c *Client) ListResourceTemplates(context.Context, mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	return &mcp.ListResourceTemplatesResult{}, nil
}
