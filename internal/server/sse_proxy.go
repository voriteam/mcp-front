package server

import (
	"bufio"
	"context"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/ioutil"
	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/pinnedargs"
)

// forwardSSEToBackend forwards an SSE request to the backend SSE server
func forwardSSEToBackend(ctx context.Context, w http.ResponseWriter, r *http.Request, config *config.MCPClientConfig) {
	// Build the backend URL - SSE servers should expose their SSE endpoint at the root
	backendURL := config.URL

	// Create the backend request
	req, err := http.NewRequestWithContext(ctx, r.Method, backendURL, nil)
	if err != nil {
		log.LogErrorWithFields("sse_proxy", "Failed to create backend request", map[string]any{
			"error": err.Error(),
			"url":   backendURL,
		})
		jsonwriter.WriteInternalServerError(w, "Failed to create request")
		return
	}

	// Copy relevant headers from original request, excluding hop-by-hop and sensitive headers
	copyRequestHeaders(req.Header, r.Header)

	// Add configured headers (e.g., auth headers)
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	// Ensure we accept SSE
	req.Header.Set("Accept", "text/event-stream")

	log.LogDebugWithFields("sse_proxy", "Forwarding SSE request to backend", map[string]any{
		"backendURL": backendURL,
		"method":     r.Method,
		"headers":    config.Headers,
	})

	// Send the request
	client := &http.Client{
		Timeout: config.Timeout,
		// Don't follow redirects automatically for SSE
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("sse_proxy", "Backend request failed", map[string]any{
			"error": err.Error(),
			"url":   backendURL,
		})
		jsonwriter.WriteServiceUnavailable(w, "Backend unavailable")
		return
	}
	defer resp.Body.Close()

	// Check if we got an SSE response
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if resp.StatusCode != http.StatusOK || mediaType != "text/event-stream" {
		body := ioutil.ReadLimited(resp.Body, 4096)
		log.LogWarnWithFields("sse_proxy", "Backend did not return SSE response", map[string]any{
			"status":      resp.StatusCode,
			"contentType": contentType,
			"url":         backendURL,
			"body":        body,
		})
		jsonwriter.WriteServiceUnavailable(w, "Backend is not an SSE server")
		return
	}

	// Set SSE headers on our response
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Copy any other headers from backend
	for k, v := range resp.Header {
		if k == "Content-Type" || k == "Cache-Control" || k == "Connection" {
			continue
		}
		w.Header()[k] = v
	}

	// Start streaming
	w.WriteHeader(http.StatusOK)

	// Get flusher for SSE
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.LogError("Response writer doesn't support flushing")
		return
	}

	streamSSEResponse(w, flusher, resp.Body, "sse_proxy", pinnedArguments(config))
}

// streamSSEResponse relays the backend's event stream to the client. With no
// pinned arguments it copies bytes as they arrive; otherwise it reframes the
// stream so tool schemas can be rewritten, which costs one event of buffering.
func streamSSEResponse(w http.ResponseWriter, flusher http.Flusher, body io.Reader, logPrefix string, pinned pinnedargs.Set) {
	if len(pinned) > 0 {
		rewriteSSEResponse(w, flusher, body, logPrefix, pinned)
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				log.LogDebugWithFields(logPrefix, "Client disconnected", map[string]any{
					"error": writeErr.Error(),
				})
				return
			}
			flusher.Flush()
		}
		if err != nil {
			if err != io.EOF {
				log.LogErrorWithFields(logPrefix, "Error reading from backend", map[string]any{
					"error": err.Error(),
				})
			}
			return
		}
	}
}

// rewriteSSEResponse accumulates one event at a time and rewrites the tool
// schemas in its payload. Every line that is not part of a data payload —
// comments, event and id fields — is relayed byte for byte.
//
// bufio.Reader rather than bufio.Scanner: a tools/list payload routinely
// exceeds the scanner's token limit.
func rewriteSSEResponse(w http.ResponseWriter, flusher http.Flusher, body io.Reader, logPrefix string, pinned pinnedargs.Set) {
	reader := bufio.NewReader(body)
	var event []string

	flushEvent := func(terminator string) bool {
		if len(event) > 0 {
			payload := pinned.RewriteResponseBody([]byte(strings.Join(event, "\n")))
			for _, line := range strings.Split(string(payload), "\n") {
				if _, err := w.Write([]byte("data: " + line + "\n")); err != nil {
					return false
				}
			}
			event = event[:0]
		}
		if _, err := w.Write([]byte(terminator)); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimRight(line, "\r\n")
			if data, ok := strings.CutPrefix(trimmed, "data:"); ok {
				event = append(event, strings.TrimPrefix(data, " "))
			} else if trimmed == "" {
				if !flushEvent(line) {
					log.LogDebugWithFields(logPrefix, "Client disconnected", nil)
					return
				}
			} else {
				// A field ordered before this event's data lines.
				if _, writeErr := w.Write([]byte(line)); writeErr != nil {
					log.LogDebugWithFields(logPrefix, "Client disconnected", nil)
					return
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.LogErrorWithFields(logPrefix, "Error reading from backend", map[string]any{
					"error": err.Error(),
				})
			}
			flushEvent("")
			return
		}
	}
}
