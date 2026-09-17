package reqlog

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordToolWithoutContextIsRefused(t *testing.T) {
	assert.False(t, RecordTool(context.Background(), ToolCall{Name: "query"}))
}

func TestRecordAndTakeRoundTrip(t *testing.T) {
	ctx, rc := Inject(context.Background())

	require.True(t, RecordTool(ctx, ToolCall{Backend: "postgres", Name: "query", DurationMS: 7}))

	tool, ok := rc.TakeTool()
	require.True(t, ok)
	assert.Equal(t, ToolCall{Backend: "postgres", Name: "query", DurationMS: 7}, tool)
}

func TestTakeToolWithNothingRecorded(t *testing.T) {
	_, rc := Inject(context.Background())

	_, ok := rc.TakeTool()
	assert.False(t, ok)
}

func TestRecordToolAfterTakeIsRefused(t *testing.T) {
	ctx, rc := Inject(context.Background())
	rc.TakeTool()

	assert.False(t, RecordTool(ctx, ToolCall{Name: "query"}))
}

// The SSE transport runs its tool handler in a goroutine that outlives the
// request, so a record can race the log line it was meant for. Run under -race.
func TestConcurrentRecordAndTake(t *testing.T) {
	ctx, rc := Inject(context.Background())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); RecordTool(ctx, ToolCall{Name: "query"}) }()
	go func() { defer wg.Done(); rc.TakeTool() }()
	wg.Wait()
}
