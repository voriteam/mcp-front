package cube

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/gateway"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultTimeout      = 30 * time.Second
	tokenTTL            = 1 * time.Hour
	tokenRefreshLeadTime = 10 * time.Minute
)

type Server struct {
	apiURL        string
	signingSecret string
	client        *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func NewServer(apiURL string, signingSecret string) *Server {
	s := &Server{
		apiURL:        strings.TrimRight(apiURL, "/"),
		signingSecret: signingSecret,
		client:        &http.Client{Timeout: defaultTimeout},
	}
	s.token, s.tokenExp = mintCubeJWT(signingSecret)
	return s
}

func (s *Server) getToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().After(s.tokenExp.Add(-tokenRefreshLeadTime)) {
		s.token, s.tokenExp = mintCubeJWT(s.signingSecret)
	}
	return s.token
}

func mintCubeJWT(secret string) (string, time.Time) {
	exp := time.Now().Add(tokenTTL)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"internal":true,"exp":%d}`, exp.Unix()),
	))
	unsigned := header + "." + payload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig, exp
}

func (s *Server) ListInlineTools() []gateway.InlineTool {
	readOnly := true
	cubeAnnotations := &mcp.ToolAnnotation{ReadOnlyHint: &readOnly}

	return []gateway.InlineTool{
		{
			Name:        "meta",
			Description: "Returns the Cube semantic model: cubes, views, measures, dimensions, joins, and descriptions. Call this first to understand what data is available before formulating queries.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			Annotations: cubeAnnotations,
		},
		{
			Name:        "query",
			Description: "Executes a structured Cube query and returns results. Use cube_meta first to discover available measures and dimensions.",
			Annotations: cubeAnnotations,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"measures": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Aggregate measures to compute (e.g. [\"Orders.count\", \"Orders.totalAmount\"])"
					},
					"dimensions": {
						"type": "array",
						"items": {"type": "string"},
						"description": "Dimensions to group by (e.g. [\"Orders.status\", \"Products.category\"])"
					},
					"filters": {
						"type": "array",
						"items": {
							"type": "object",
							"properties": {
								"member": {"type": "string"},
								"operator": {"type": "string", "enum": ["equals","notEquals","contains","notContains","startsWith","endsWith","gt","gte","lt","lte","set","notSet","inDateRange","notInDateRange","beforeDate","beforeOrOnDate","afterDate","afterOrOnDate"]},
								"values": {"type": "array", "items": {"type": "string"}}
							},
							"required": ["member", "operator"]
						},
						"description": "Filters to apply"
					},
					"timeDimensions": {
						"type": "array",
						"items": {
							"type": "object",
							"properties": {
								"dimension": {"type": "string"},
								"dateRange": {},
								"granularity": {"type": "string", "enum": ["second","minute","hour","day","week","month","quarter","year"]}
							},
							"required": ["dimension"]
						},
						"description": "Time-based dimensions with optional date ranges and granularity"
					},
					"limit": {
						"type": "integer",
						"description": "Maximum number of rows to return"
					},
					"offset": {
						"type": "integer",
						"description": "Number of rows to skip"
					},
					"order": {
						"description": "Sort order as object mapping member names to 'asc' or 'desc'"
					},
					"timezone": {
						"type": "string",
						"description": "Timezone for time dimension calculations (e.g. \"America/New_York\")"
					}
				},
				"required": ["measures"]
			}`),
		},
		{
			Name:        "dimension_search",
			Description: "Searches for matching values of a dimension. Use this to resolve ambiguous references like store names, product names, or categories before querying.",
			Annotations: cubeAnnotations,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dimension": {
						"type": "string",
						"description": "The dimension to search (e.g. \"Stores.name\")"
					},
					"query": {
						"type": "string",
						"description": "Search term to match against dimension values (case-insensitive contains)"
					}
				},
				"required": ["dimension", "query"]
			}`),
		},
	}
}

func (s *Server) CallInlineTool(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case "meta":
		return s.callMeta(ctx)
	case "query":
		return s.callQuery(ctx, args)
	case "dimension_search":
		return s.callDimensionSearch(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func (s *Server) callMeta(ctx context.Context) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL+"/v1/meta", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return s.doRequest(req)
}

func (s *Server) callQuery(ctx context.Context, args map[string]any) (any, error) {
	body, err := json.Marshal(map[string]any{"query": args})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+"/v1/load", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return s.doRequest(req)
}

func (s *Server) callDimensionSearch(ctx context.Context, args map[string]any) (any, error) {
	dimension, _ := args["dimension"].(string)
	query, _ := args["query"].(string)
	if dimension == "" || query == "" {
		return nil, fmt.Errorf("dimension and query are required")
	}

	cubeQuery := map[string]any{
		"dimensions": []string{dimension},
		"filters": []map[string]any{
			{
				"member":   dimension,
				"operator": "contains",
				"values":   []string{query},
			},
		},
		"limit": 100,
	}

	body, err := json.Marshal(map[string]any{"query": cubeQuery})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+"/v1/load", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return s.doRequest(req)
}

func (s *Server) doRequest(req *http.Request) (any, error) {
	req.Header.Set("Authorization", s.getToken())

	log.LogDebug("Cube API request: %s %s", req.Method, req.URL.String())

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cube API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cube API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return map[string]any{"output": string(respBody)}, nil
	}
	return result, nil
}
