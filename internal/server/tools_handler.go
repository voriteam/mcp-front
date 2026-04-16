package server

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stainless-api/mcp-front/internal/aggregate"
	"github.com/stainless-api/mcp-front/internal/config"
	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
)

// ToolsPageData represents the data for the tools listing page.
type ToolsPageData struct {
	UserEmail    string
	TotalTools   int
	ServiceCount int
	Services     []ServiceTools
	Error        string
}

// ToolInfo represents a tool for display purposes.
type ToolInfo struct {
	Name        string
	Description string
	Annotations mcp.ToolAnnotation
}

// ServiceTools groups tools by service for display purposes.
type ServiceTools struct {
	Name              string
	Tools             []ToolInfo
	RequiresUserToken bool
	NeedsAuth         bool
}

// ToolsHandler serves the aggregate tools listing page.
type ToolsHandler struct {
	aggregate *aggregate.Server
}

// NewToolsHandler creates a new tools handler.
func NewToolsHandler(agg *aggregate.Server) *ToolsHandler {
	return &ToolsHandler{aggregate: agg}
}

func (h *ToolsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, _ := oauth.GetUserFromContext(r.Context())
	if userEmail == "" {
		jsonwriter.WriteUnauthorized(w, "Authentication required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	toolsByBackend, err := h.aggregate.ListToolsByBackend(ctx, userEmail)

	data := ToolsPageData{UserEmail: userEmail}

	if err != nil {
		log.LogErrorWithFields("tools", "Failed to list tools", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		data.Error = err.Error()
	} else {
		backends := h.aggregate.Backends()
		data.Services = buildServiceTools(backends, toolsByBackend)
		data.ServiceCount = len(data.Services)
		for _, svc := range data.Services {
			data.TotalTools += len(svc.Tools)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := toolsPageTemplate.Execute(w, data); err != nil {
		log.LogErrorWithFields("tools", "Failed to render tools page", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
	}
}

func buildServiceTools(backends map[string]*config.MCPClientConfig, toolsByBackend map[string][]mcp.Tool) []ServiceTools {
	result := make([]ServiceTools, 0, len(backends))
	for name, conf := range backends {
		tools := toolsByBackend[name]
		infos := make([]ToolInfo, 0, len(tools))
		for _, t := range tools {
			infos = append(infos, ToolInfo{
				Name:        t.Name,
				Description: t.Description,
				Annotations: t.Annotations,
			})
		}
		sort.Slice(infos, func(i, j int) bool {
			return infos[i].Name < infos[j].Name
		})

		requiresToken := conf.RequiresUserToken
		needsAuth := requiresToken && len(infos) == 0

		result = append(result, ServiceTools{
			Name:              name,
			Tools:             infos,
			RequiresUserToken: requiresToken,
			NeedsAuth:         needsAuth,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].NeedsAuth != result[j].NeedsAuth {
			return result[i].NeedsAuth
		}
		return result[i].Name < result[j].Name
	})

	return result
}
