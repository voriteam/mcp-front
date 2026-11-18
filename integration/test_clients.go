package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MCPClient is a streamable-http MCP client for tests. ConnectToServer runs the
// initialize handshake and later requests carry the session ID it returns.
type MCPClient struct {
	baseURL    string
	token      string
	serverName string
	sessionID  string
	nextID     int
	httpClient *http.Client
}

func NewMCPClient(baseURL string) *MCPClient {
	return &MCPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// Authenticate sets the default bearer token most test configs accept.
func (c *MCPClient) Authenticate() error {
	c.token = "test-token"
	return nil
}

func (c *MCPClient) SetAuthToken(token string) {
	c.token = token
}

// Connect connects to the "postgres" server, the default in most test configs.
func (c *MCPClient) Connect() error {
	return c.ConnectToServer("postgres")
}

func (c *MCPClient) ValidateBackendConnectivity() error {
	return c.Connect()
}

func (c *MCPClient) ConnectToServer(serverName string) error {
	c.serverName = serverName
	c.sessionID = ""

	resp, header, err := c.post(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.newID(),
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "integration-test", "version": "1.0"},
		},
	})
	if err != nil {
		c.serverName = ""
		return fmt.Errorf("initialize failed: %w", err)
	}
	if errObj, ok := resp["error"]; ok {
		c.serverName = ""
		return fmt.Errorf("initialize returned error: %v", errObj)
	}
	c.sessionID = header.Get("Mcp-Session-Id")

	if _, _, err := c.post(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}); err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}
	return nil
}

func (c *MCPClient) Close() {
	c.serverName = ""
	c.sessionID = ""
}

func (c *MCPClient) SendMCPRequest(method string, params any) (map[string]any, error) {
	if c.serverName == "" {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	}

	resp, _, err := c.post(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.newID(),
		"method":  method,
		"params":  params,
	})
	return resp, err
}

func (c *MCPClient) newID() int {
	c.nextID++
	return c.nextID
}

// post sends one JSON-RPC message. Notifications return a nil message.
func (c *MCPClient) post(message map[string]any) (map[string]any, http.Header, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/"+c.serverName, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return nil, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, resp.Header, fmt.Errorf("MCP request failed: %d - %s", resp.StatusCode, string(respBody))
	}
	if _, isRequest := message["id"]; !isRequest {
		return nil, resp.Header, nil
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		result, err := readSSEResponse(resp.Body)
		return result, resp.Header, err
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.Header, fmt.Errorf("failed to decode JSON response: %w", err)
	}
	return result, resp.Header, nil
}

// readSSEResponse returns the last message carrying an ID from an SSE response.
func readSSEResponse(body io.Reader) (map[string]any, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var last map[string]any
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data:")
		if !ok {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &msg); err != nil {
			continue
		}
		if _, hasID := msg["id"]; hasID {
			last = msg
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		return nil, fmt.Errorf("no response received in SSE stream")
	}
	return last, nil
}
