// Standalone reproducer for the streamable-http + aggregate tools/list issue.
//
// Run with: go run ./internal/aggregate/streamable_race_test
//
// Starts a mock streamable-http backend with tools, an aggregate server exposing
// streamable-http, and hits it with raw HTTP to see whether tools/list returns
// the backend's tools or an empty list.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stainless-api/mcp-front/internal/aggregate"
	"github.com/stainless-api/mcp-front/internal/client"
	"github.com/stainless-api/mcp-front/internal/config"
)

func main() {
	// 1. Start a backend MCP server with 3 tools (streamable-http transport).
	backendMCP := mcpserver.NewMCPServer("backend", "1.0.0", mcpserver.WithToolCapabilities(true))
	for _, name := range []string{"tool_a", "tool_b", "tool_c"} {
		tool := mcp.NewTool(name, mcp.WithDescription("Test "+name))
		backendMCP.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("result"), nil
		})
	}
	backendStreamable := mcpserver.NewStreamableHTTPServer(backendMCP,
		mcpserver.WithEndpointPath("/"),
	)
	backendSrv := httptest.NewServer(backendStreamable)
	defer backendSrv.Close()
	fmt.Printf("Backend running at %s\n", backendSrv.URL)

	// 2. Build an aggregate server using streamable-http transport.
	backendCfg := &config.MCPClientConfig{
		TransportType: config.MCPClientTypeStreamable,
		URL:           backendSrv.URL + "/",
	}
	agg := aggregate.NewServer(aggregate.ServerConfig{
		Name:            "aggregate",
		TransportType:   config.MCPClientTypeStreamable,
		Backends:        map[string]*config.MCPClientConfig{"backend": backendCfg},
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		Delimiter:       ".",
		CreateTransport: client.DefaultTransportCreator,
		BaseURL:         "http://localhost:0",
	})
	agg.Start()
	defer agg.Shutdown(context.Background())

	// Upstream's aggregate uses streamable-http when ServerConfig.TransportType is streamable-http.
	// But we removed that field. To force streamable-http, we call the internal wiring manually.
	// Instead, just test via HTTP: the Handler() returns something that speaks streamable-http
	// based on how NewServer was configured.
	mux := http.NewServeMux()
	mux.Handle("/aggregate/", agg.Handler())
	mux.Handle("/aggregate", agg.Handler())
	frontSrv := httptest.NewServer(mux)
	defer frontSrv.Close()
	fmt.Printf("Aggregate running at %s/aggregate/\n\n", frontSrv.URL)

	// 3. Run the test: initialize then tools/list.
	runTest(frontSrv.URL + "/aggregate/")
}

func runTest(baseURL string) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	// POST initialize
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test-client", "version": "1.0"},
		},
	}
	initBody, _ := json.Marshal(initReq)
	req, _ := http.NewRequest("POST", baseURL, bytes.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	fmt.Println("→ POST initialize")
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("initialize failed: %v", err)
	}
	initRespBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("  Status: %d\n", resp.StatusCode)
	fmt.Printf("  Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("  Mcp-Session-Id: %s\n", resp.Header.Get("Mcp-Session-Id"))
	fmt.Printf("  Body (%d bytes): %s\n\n", len(initRespBody), truncate(string(initRespBody), 200))

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		fmt.Println("⚠️  No Mcp-Session-Id header returned; continuing without")
	}

	// POST initialized notification
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifBody, _ := json.Marshal(notif)
	req, _ = http.NewRequest("POST", baseURL, bytes.NewReader(notifBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	fmt.Println("→ POST notifications/initialized")
	resp, err = httpClient.Do(req)
	if err != nil {
		log.Fatalf("initialized failed: %v", err)
	}
	resp.Body.Close()
	fmt.Printf("  Status: %d\n\n", resp.StatusCode)

	// POST tools/list
	toolsListReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	toolsBody, _ := json.Marshal(toolsListReq)
	req, _ = http.NewRequest("POST", baseURL, bytes.NewReader(toolsBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	// Wait a bit to ensure any deferred work completes
	time.Sleep(200 * time.Millisecond)

	fmt.Println("→ POST tools/list")
	resp, err = httpClient.Do(req)
	if err != nil {
		log.Fatalf("tools/list failed: %v", err)
	}
	toolsRespBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("  Status: %d\n", resp.StatusCode)
	fmt.Printf("  Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("  Body (%d bytes): %s\n\n", len(toolsRespBody), truncate(string(toolsRespBody), 500))

	// Parse and count tools
	var toolsResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(toolsRespBody, &toolsResp); err != nil {
		// Try SSE-encoded response
		text := string(toolsRespBody)
		fmt.Printf("⚠️  Response isn't plain JSON; raw body shown above\n\n")
		_ = text
	}

	fmt.Printf("=== RESULT ===\n")
	fmt.Printf("Tools returned: %d\n", len(toolsResp.Result.Tools))
	for _, t := range toolsResp.Result.Tools {
		fmt.Printf("  - %s\n", t.Name)
	}

	if len(toolsResp.Result.Tools) == 0 {
		fmt.Println("\n❌ BUG CONFIRMED: tools/list returned empty via streamable-http (aggregate backend has 3 tools)")
		os.Exit(1)
	}
	fmt.Println("\n✅ tools/list returned the expected tools")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
