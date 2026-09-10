package builtin

import (
	"fmt"

	"github.com/stainless-api/mcp-front/internal/client"
	"github.com/stainless-api/mcp-front/internal/config"
)

// Registry maps a builtin server's `builtin` config key to its tool set.
type Registry map[string][]Tool

// TransportCreator serves builtin servers in process and delegates the rest.
func TransportCreator(reg Registry, next client.TransportCreator) client.TransportCreator {
	return func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		if conf.TransportType != config.MCPClientTypeBuiltin {
			return next(conf)
		}
		tools, ok := reg[conf.Builtin]
		if !ok {
			return nil, fmt.Errorf("unknown builtin server %q", conf.Builtin)
		}
		return NewClient(conf.Builtin, conf.UserEmail, tools), nil
	}
}
