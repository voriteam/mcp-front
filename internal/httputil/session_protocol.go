package httputil

import (
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
)

func RequireSessionProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version := r.Header.Get(mcp.HeaderProtocolVersion); mcp.IsModernProtocol(version) {
			http.Error(w, "protocol version "+version+" is not supported, use initialize", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
