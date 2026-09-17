package testutil

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// CaptureLogs redirects the default logger for the duration of the test. The
// returned function decodes everything logged so far.
func CaptureLogs(t *testing.T) func() []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return func() []map[string]any {
		var records []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("log line is not JSON: %v", err)
			}
			records = append(records, record)
		}
		return records
	}
}
