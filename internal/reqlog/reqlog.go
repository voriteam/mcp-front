// Package reqlog carries log fields from deep inside a request's handling up to
// the canonical log line emitted when that request finishes.
package reqlog

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type contextKey struct{}

// ToolCall describes one proxied MCP tool call. Arguments and results are
// deliberately absent: the gateway records that a tool ran, never what ran
// through it.
type ToolCall struct {
	Backend    string
	Name       string
	SessionID  string
	DurationMS int64
	Failed     bool
}

type Context struct {
	mu     sync.Mutex
	tool   *ToolCall
	closed bool
}

func Inject(ctx context.Context) (context.Context, *Context) {
	rc := &Context{}
	return context.WithValue(ctx, contextKey{}, rc), rc
}

// RecordTool reports whether the call will reach the request's log line. It
// reports false once that line has been emitted, which is the ordinary case
// under the SSE transport, where the tool handler runs in a goroutine after the
// response; the caller logs the call itself then.
func RecordTool(ctx context.Context, t ToolCall) bool {
	rc, ok := ctx.Value(contextKey{}).(*Context)
	if !ok {
		return false
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.closed {
		return false
	}
	rc.tool = &t
	return true
}

// TakeTool closes c to further writes and returns whatever was recorded.
func (c *Context) TakeTool() (ToolCall, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.tool == nil {
		return ToolCall{}, false
	}
	return *c.tool, true
}

// FormatDuration renders sub-second durations in whole milliseconds and longer
// ones such as held-open streams in minutes and seconds.
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Round(time.Millisecond).String()
}
