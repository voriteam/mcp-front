package server

import (
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/pinnedargs"
)

func pinnedArguments(conf *config.MCPClientConfig) pinnedargs.Set {
	if conf == nil || conf.Options == nil {
		return nil
	}
	return conf.Options.PinnedArguments
}
