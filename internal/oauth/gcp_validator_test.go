package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	opsbotServiceAccount   = "opsbot@example-project.iam.gserviceaccount.com"
	coderServiceAccount    = "coder@example-project.iam.gserviceaccount.com"
	outsiderServiceAccount = "outsider@other-project.iam.gserviceaccount.com"

	callerRole       = "projects/example-project/roles/mcpGatewayCaller"
	impersonatorRole = "projects/example-project/roles/mcpGatewayImpersonator"
)

// fakeRoles maps a role to the service accounts bound to it.
type fakeRoles map[string][]string

func (f fakeRoles) HasRole(_ context.Context, role, serviceAccount string) (bool, error) {
	return slices.Contains(f[role], serviceAccount), nil
}

type failingRoles struct{}

func (failingRoles) HasRole(context.Context, string, string) (bool, error) {
	return false, errors.New("IAM unavailable")
}

func newFakeTokenInfo(t *testing.T, emails map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := emails[r.URL.Query().Get("access_token")]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"email":          email,
			"email_verified": "true",
			"expires_in":     "3600",
		}))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestGCPAccessTokenValidator_Validate(t *testing.T) {
	tokenInfoURL := newFakeTokenInfo(t, map[string]string{
		"opsbot-token":   opsbotServiceAccount,
		"outsider-token": outsiderServiceAccount,
		"human-token":    "alice@example.com",
	})

	callers := fakeRoles{callerRole: {opsbotServiceAccount}}

	cases := []struct {
		name       string
		roles      RoleChecker
		callerRole string
		token      string
		wantEmail  string
	}{
		{name: "service account with the caller role", roles: callers, callerRole: callerRole, token: "opsbot-token", wantEmail: opsbotServiceAccount},
		{name: "service account without the caller role", roles: callers, callerRole: callerRole, token: "outsider-token"},
		{name: "user account", roles: callers, callerRole: callerRole, token: "human-token"},
		{name: "no caller role rejects every account", roles: callers, token: "opsbot-token"},
		{name: "failed role check rejects", roles: failingRoles{}, callerRole: callerRole, token: "opsbot-token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewGCPAccessTokenValidator(GCPAccessTokenValidatorConfig{
				TokenInfoURL: tokenInfoURL,
				Roles:        tc.roles,
				CallerRole:   tc.callerRole,
			})

			email, err := v.Validate(context.Background(), tc.token)
			if tc.wantEmail == "" {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "@")
				assert.Empty(t, email)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantEmail, email)
		})
	}
}
