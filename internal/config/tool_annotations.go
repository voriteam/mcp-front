package config

import "github.com/mark3labs/mcp-go/mcp"

// ApplyToolAnnotations overlays the configured override for tool.Name, if any,
// onto the annotations the backend advertised. Hints the override leaves unset
// keep the backend's value. Safe to call on a nil receiver.
func (o *Options) ApplyToolAnnotations(tool mcp.Tool) mcp.Tool {
	if o == nil {
		return tool
	}
	override, ok := o.ToolAnnotations[tool.Name]
	if !ok {
		return tool
	}
	if override.ReadOnlyHint != nil {
		tool.Annotations.ReadOnlyHint = override.ReadOnlyHint
	}
	if override.DestructiveHint != nil {
		tool.Annotations.DestructiveHint = override.DestructiveHint
	}
	if override.IdempotentHint != nil {
		tool.Annotations.IdempotentHint = override.IdempotentHint
	}
	if override.OpenWorldHint != nil {
		tool.Annotations.OpenWorldHint = override.OpenWorldHint
	}
	return tool
}
