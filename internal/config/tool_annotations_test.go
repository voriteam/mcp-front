package config

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestApplyToolAnnotations(t *testing.T) {
	trueVal, falseVal := true, false
	backendTool := mcp.Tool{
		Name:        "execute_sql",
		Annotations: mcp.ToolAnnotation{Title: "Execute SQL", ReadOnlyHint: &falseVal, DestructiveHint: &trueVal},
	}

	t.Run("nil options pass the tool through", func(t *testing.T) {
		var opts *Options
		assert.Equal(t, backendTool, opts.ApplyToolAnnotations(backendTool))
	})

	t.Run("no entry for the tool passes it through", func(t *testing.T) {
		opts := &Options{ToolAnnotations: map[string]ToolAnnotationOverride{"other": {ReadOnlyHint: &trueVal}}}
		assert.Equal(t, backendTool, opts.ApplyToolAnnotations(backendTool))
	})

	t.Run("set hints override, unset hints and title are kept", func(t *testing.T) {
		opts := &Options{ToolAnnotations: map[string]ToolAnnotationOverride{
			"execute_sql": {ReadOnlyHint: &trueVal, DestructiveHint: &falseVal, IdempotentHint: &trueVal},
		}}
		got := opts.ApplyToolAnnotations(backendTool)
		assert.Equal(t, mcp.ToolAnnotation{
			Title:           "Execute SQL",
			ReadOnlyHint:    &trueVal,
			DestructiveHint: &falseVal,
			IdempotentHint:  &trueVal,
		}, got.Annotations)
		assert.Equal(t, "execute_sql", got.Name)
	})

	t.Run("open world hint is applied", func(t *testing.T) {
		opts := &Options{ToolAnnotations: map[string]ToolAnnotationOverride{"execute_sql": {OpenWorldHint: &falseVal}}}
		got := opts.ApplyToolAnnotations(backendTool)
		assert.Equal(t, mcp.ToolAnnotation{
			Title:           "Execute SQL",
			ReadOnlyHint:    &falseVal,
			DestructiveHint: &trueVal,
			OpenWorldHint:   &falseVal,
		}, got.Annotations)
	})
}
