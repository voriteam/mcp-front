package server

import (
	_ "embed"
	"html/template"
)

//go:embed templates/tokens.html
var tokenPageTemplateHTML string

//go:embed templates/services.html
var servicesPageTemplateHTML string

//go:embed templates/tools.html
var toolsPageTemplateHTML string

//go:embed templates/connections.html
var connectionsPageTemplateHTML string

var toolsFuncMap = template.FuncMap{
	"isTrue": func(b *bool) bool { return b != nil && *b },
}

var tokenPageTemplate = template.Must(template.New("tokens").Parse(tokenPageTemplateHTML))
var servicesPageTemplate = template.Must(template.New("services").Parse(servicesPageTemplateHTML))
var toolsPageTemplate = template.Must(template.New("tools").Funcs(toolsFuncMap).Parse(toolsPageTemplateHTML))
var connectionsPageTemplate = template.Must(template.New("connections").Parse(connectionsPageTemplateHTML))

// TokenPageData represents the data for the token management page
type TokenPageData struct {
	UserEmail   string
	Services    []ServiceTokenData
	CSRFToken   string
	Message     string
	MessageType string // "success" or "error"
}

// ServiceTokenData represents a single service in the token page
type ServiceTokenData struct {
	Name             string
	DisplayName      string
	Instructions     string
	HelpURL          string
	TokenFormat      string
	HasToken         bool
	RequiresToken    bool
	AuthType         string // "oauth", "bearer", or "none"
	SupportsOAuth    bool   // Whether this service supports OAuth authentication
	IsOAuthConnected bool   // Whether the user has connected OAuth for this service
	IsExpired        bool   // Whether the OAuth token has expired without a refresh token
	ConnectURL       string // Pre-generated OAuth connect URL
}

// ServicesPageData represents the data for the service selection page
type ServicesPageData struct {
	Services    []ServiceSelectionData
	State       string
	ReturnURL   string
	Message     string
	MessageType string // "success" or "error"
}

// ServiceSelectionData represents a single service in the selection page
type ServiceSelectionData struct {
	Name        string
	DisplayName string
	Status      string // "not_connected", "connected", "expired", "error"
	ErrorMsg    string
	ConnectURL  string // Pre-generated OAuth connect URL
}

// ConnectionsPageData represents the data for the all-users connections page.
// It is shown to every signed-in user, so it holds connection metadata only.
type ConnectionsPageData struct {
	ViewerEmail string
	Filter      string
	Columns     []ConnectionColumnData
	Rows        []ConnectionRowData
	Orphans     []OrphanedConnectionData
	TotalUsers  int
}

// ConnectionColumnData is one MCP that needs a per-user connection
type ConnectionColumnData struct {
	Name           string
	DisplayName    string
	ConnectedCount int
}

// ConnectionRowData is one user, with a cell per column
type ConnectionRowData struct {
	UserEmail string
	Cells     []ConnectionCellData
}

// ConnectionCellData is one user's connection to one MCP
type ConnectionCellData struct {
	Connected   bool
	Type        string // "oauth" or "manual"
	UpdatedAt   string
	Expired     bool
	Refreshable bool
}

// OrphanedConnectionData is a stored connection for an MCP no longer in config
type OrphanedConnectionData struct {
	UserEmail string
	Service   string
	Type      string
	UpdatedAt string
}
