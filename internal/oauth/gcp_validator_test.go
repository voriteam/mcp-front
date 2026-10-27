package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	opsbotServiceAccount   = "opsbot@example-project.iam.gserviceaccount.com"
	coderServiceAccount    = "coder@example-project.iam.gserviceaccount.com"
	outsiderServiceAccount = "outsider@other-project.iam.gserviceaccount.com"
)

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

	cases := []struct {
		name      string
		allowed   []string
		token     string
		wantEmail string
	}{
		{name: "allowed service account", allowed: []string{opsbotServiceAccount}, token: "opsbot-token", wantEmail: opsbotServiceAccount},
		{name: "service account not on the list", allowed: []string{opsbotServiceAccount}, token: "outsider-token"},
		{name: "user account", allowed: []string{opsbotServiceAccount}, token: "human-token"},
		{name: "empty list rejects every account", allowed: nil, token: "opsbot-token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewGCPAccessTokenValidator(GCPAccessTokenValidatorConfig{
				TokenInfoURL:           tokenInfoURL,
				AllowedServiceAccounts: tc.allowed,
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
