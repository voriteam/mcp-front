package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

func newFakeIAM(t *testing.T, policy map[string]any) (*ProjectIAMRoles, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	var calls atomic.Int32
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "/v1/projects/example-project:getIamPolicy", r.URL.Path)
		if failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(policy))
	}))
	t.Cleanup(srv.Close)

	roles, err := NewProjectIAMRoles(context.Background(), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	require.NoError(t, err)
	return roles, &calls, &failing
}

func TestProjectIAMRoles_HasRole(t *testing.T) {
	roles, _, _ := newFakeIAM(t, map[string]any{
		"version": 3,
		"bindings": []map[string]any{
			{"role": callerRole, "members": []string{"serviceAccount:" + opsbotServiceAccount}},
			{
				"role":      impersonatorRole,
				"members":   []string{"serviceAccount:" + coderServiceAccount},
				"condition": map[string]string{"title": "expires", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
			},
			{"role": "roles/owner", "members": []string{"serviceAccount:" + outsiderServiceAccount}},
		},
	})

	cases := []struct {
		name           string
		role           string
		serviceAccount string
		want           bool
	}{
		{name: "direct binding", role: callerRole, serviceAccount: opsbotServiceAccount, want: true},
		{name: "account bound to another role", role: callerRole, serviceAccount: outsiderServiceAccount},
		{name: "conditional binding does not count", role: impersonatorRole, serviceAccount: coderServiceAccount},
		{name: "role with no binding", role: impersonatorRole, serviceAccount: opsbotServiceAccount},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roles.HasRole(context.Background(), tc.role, tc.serviceAccount)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := roles.HasRole(context.Background(), "roles/viewer", opsbotServiceAccount)
	assert.Error(t, err)
}

func TestProjectIAMRoles_CachesAndFallsBackToTheLastPolicy(t *testing.T) {
	roles, calls, failing := newFakeIAM(t, map[string]any{
		"bindings": []map[string]any{
			{"role": callerRole, "members": []string{"serviceAccount:" + opsbotServiceAccount}},
		},
	})
	ctx := context.Background()

	for range 3 {
		ok, err := roles.HasRole(ctx, callerRole, opsbotServiceAccount)
		require.NoError(t, err)
		assert.True(t, ok)
	}
	assert.Equal(t, int32(1), calls.Load(), "policy is read once per TTL")

	failing.Store(true)
	roles.policies["example-project"].fetchedAt = time.Now().Add(-2 * policyTTL)
	ok, err := roles.HasRole(ctx, callerRole, opsbotServiceAccount)
	require.NoError(t, err, "a failed refresh falls back to the last policy")
	assert.True(t, ok)

	roles.policies["example-project"].fetchedAt = time.Now().Add(-2 * policyMaxStale)
	_, err = roles.HasRole(ctx, callerRole, opsbotServiceAccount)
	assert.Error(t, err, "a policy older than the stale limit is not used")
}
