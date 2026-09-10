package client

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/pinnedargs"
)

// pinnedClient hides a server's pinned arguments from the tools it advertises
// and sets them on every call it forwards.
type pinnedClient struct {
	MCPClientInterface
	pinned pinnedargs.Set
}

// withPinnedArguments wraps inner when conf pins any tool-call argument.
func withPinnedArguments(inner MCPClientInterface, conf *config.MCPClientConfig) MCPClientInterface {
	if conf == nil || conf.Options == nil || len(conf.Options.PinnedArguments) == 0 {
		return inner
	}
	return &pinnedClient{MCPClientInterface: inner, pinned: conf.Options.PinnedArguments}
}

// WithPinnedArguments decorates a transport creator so every client it builds
// applies its server's pinned arguments.
func WithPinnedArguments(next TransportCreator) TransportCreator {
	return func(conf *config.MCPClientConfig) (MCPClientInterface, error) {
		inner, err := next(conf)
		if err != nil {
			return nil, err
		}
		return withPinnedArguments(inner, conf), nil
	}
}

func (c *pinnedClient) ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	result, err := c.MCPClientInterface.ListTools(ctx, request)
	if err != nil {
		return nil, err
	}
	c.pinned.RewriteTools(result.Tools)
	return result, nil
}

func (c *pinnedClient) CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	request.Params.Arguments = c.pinned.Apply(request.Params.Arguments)
	return c.MCPClientInterface.CallTool(ctx, request)
}
