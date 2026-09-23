package server

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/storage"
)

type connectionDirectory interface {
	ListUserTokenMetadata(ctx context.Context) ([]storage.UserTokenMetadata, error)
	ListIdentityTokenUsers(ctx context.Context) ([]string, error)
}

// ConnectionsHandler renders every user's connection status for each MCP that
// needs a per-user connection. Any signed-in user may view it.
type ConnectionsHandler struct {
	store   connectionDirectory
	columns []connectionColumn
}

type connectionColumn struct {
	name        string
	displayName string
}

func NewConnectionsHandler(store connectionDirectory, mcpServers map[string]*config.MCPClientConfig) *ConnectionsHandler {
	var columns []connectionColumn
	for name, serverConfig := range mcpServers {
		if !serverConfig.RequiresUserToken {
			continue
		}
		displayName := name
		if serverConfig.UserAuthentication != nil && serverConfig.UserAuthentication.DisplayName != "" {
			displayName = serverConfig.UserAuthentication.DisplayName
		}
		columns = append(columns, connectionColumn{name: name, displayName: displayName})
	}
	slices.SortFunc(columns, func(a, b connectionColumn) int { return strings.Compare(a.name, b.name) })

	return &ConnectionsHandler{store: store, columns: columns}
}

func (h *ConnectionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	filter := strings.TrimSpace(r.URL.Query().Get("q"))

	log.LogInfoWithFields("connections", "Viewed connections page", map[string]any{
		"user":   userEmail,
		"filter": filter,
	})

	tokens, err := h.store.ListUserTokenMetadata(r.Context())
	if err != nil {
		log.LogErrorWithFields("connections", "Failed to list user tokens", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	identityUsers, err := h.store.ListIdentityTokenUsers(r.Context())
	if err != nil {
		log.LogErrorWithFields("connections", "Failed to list signed-in users", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	data := buildConnectionsPage(h.columns, identityUsers, tokens, time.Now(), filter)
	data.ViewerEmail = userEmail

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := connectionsPageTemplate.Execute(w, data); err != nil {
		log.LogErrorWithFields("connections", "Failed to render connections page", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

const connectionTimeFormat = "2006-01-02 15:04 MST"

// buildConnectionsPage computes per-MCP totals over every user; the email
// filter narrows only the rows and orphans shown.
func buildConnectionsPage(columns []connectionColumn, identityUsers []string, tokens []storage.UserTokenMetadata, now time.Time, filter string) ConnectionsPageData {
	columnIndex := make(map[string]int, len(columns))
	data := ConnectionsPageData{Filter: filter}
	for i, c := range columns {
		columnIndex[c.name] = i
		data.Columns = append(data.Columns, ConnectionColumnData{Name: c.name, DisplayName: c.displayName})
	}

	cellsByUser := map[string][]ConnectionCellData{}
	addUser := func(email string) []ConnectionCellData {
		cells, ok := cellsByUser[email]
		if !ok {
			cells = make([]ConnectionCellData, len(columns))
			cellsByUser[email] = cells
		}
		return cells
	}

	for _, email := range identityUsers {
		addUser(email)
	}

	matches := func(email string) bool {
		return filter == "" || strings.Contains(strings.ToLower(email), strings.ToLower(filter))
	}

	for _, t := range tokens {
		cells := addUser(t.UserEmail)
		i, configured := columnIndex[t.Service]
		if !configured {
			if matches(t.UserEmail) {
				data.Orphans = append(data.Orphans, OrphanedConnectionData{
					UserEmail: t.UserEmail,
					Service:   t.Service,
					Type:      string(t.Type),
					UpdatedAt: formatConnectionTime(t.UpdatedAt),
				})
			}
			continue
		}

		expired := t.Type == storage.TokenTypeOAuth && !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
		cells[i] = ConnectionCellData{
			Connected:   true,
			Type:        string(t.Type),
			UpdatedAt:   formatConnectionTime(t.UpdatedAt),
			Expired:     expired,
			Refreshable: expired && t.HasRefreshToken,
		}
		data.Columns[i].ConnectedCount++
	}

	for email, cells := range cellsByUser {
		if matches(email) {
			data.Rows = append(data.Rows, ConnectionRowData{UserEmail: email, Cells: cells})
		}
	}
	slices.SortFunc(data.Rows, func(a, b ConnectionRowData) int { return strings.Compare(a.UserEmail, b.UserEmail) })
	slices.SortFunc(data.Orphans, func(a, b OrphanedConnectionData) int {
		if c := strings.Compare(a.Service, b.Service); c != 0 {
			return c
		}
		return strings.Compare(a.UserEmail, b.UserEmail)
	})
	data.TotalUsers = len(cellsByUser)

	return data
}

func formatConnectionTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(connectionTimeFormat)
}
