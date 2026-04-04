package reqlog

import "context"

type contextKey struct{}

// Context holds per-request log fields populated by middlewares.
type Context struct {
	User    string
	TraceID string
}

// Inject adds a Context to ctx and returns the updated ctx and a pointer to the Context.
func Inject(ctx context.Context) (context.Context, *Context) {
	rc := &Context{}
	return context.WithValue(ctx, contextKey{}, rc), rc
}

// SetUser stores the authenticated user in the request log context, if present.
func SetUser(ctx context.Context, user string) {
	if rc, ok := ctx.Value(contextKey{}).(*Context); ok {
		rc.User = user
	}
}

// Get returns the request log context from ctx.
func Get(ctx context.Context) (*Context, bool) {
	rc, ok := ctx.Value(contextKey{}).(*Context)
	return rc, ok
}
