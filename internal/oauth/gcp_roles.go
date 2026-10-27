package oauth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"

	"github.com/stainless-api/mcp-front/internal/log"
)

const (
	policyTTL = time.Minute
	// A failed policy read falls back to the last one read, so a brief IAM
	// outage does not lock every service account out.
	policyMaxStale = 10 * time.Minute
	policyTimeout  = 10 * time.Second
)

// RoleChecker reports whether a service account holds a project IAM role.
type RoleChecker interface {
	HasRole(ctx context.Context, role, serviceAccount string) (bool, error)
}

type projectPolicy struct {
	// members maps a role name to the principals bound to it.
	members   map[string]map[string]bool
	fetchedAt time.Time
}

// ProjectIAMRoles reads role bindings from project IAM policies. Only direct,
// unconditional bindings on the project count. Grants inherited from a folder
// or organization, and bindings with a condition, do not.
type ProjectIAMRoles struct {
	svc      *cloudresourcemanager.Service
	mu       sync.Mutex
	policies map[string]*projectPolicy
}

func NewProjectIAMRoles(ctx context.Context, opts ...option.ClientOption) (*ProjectIAMRoles, error) {
	svc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating Cloud Resource Manager client: %w", err)
	}
	return &ProjectIAMRoles{svc: svc, policies: map[string]*projectPolicy{}}, nil
}

func (p *ProjectIAMRoles) HasRole(ctx context.Context, role, serviceAccount string) (bool, error) {
	project, ok := roleProject(role)
	if !ok {
		return false, fmt.Errorf("role %q is not a custom project role", role)
	}
	policy, err := p.policy(ctx, project)
	if err != nil {
		return false, err
	}
	return policy.members[role]["serviceAccount:"+serviceAccount], nil
}

func (p *ProjectIAMRoles) policy(ctx context.Context, project string) (*projectPolicy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	cached := p.policies[project]
	if cached != nil && time.Since(cached.fetchedAt) < policyTTL {
		return cached, nil
	}

	fetched, err := p.fetch(ctx, project)
	if err != nil {
		if cached != nil && time.Since(cached.fetchedAt) < policyMaxStale {
			log.LogWarnWithFields("gcp_auth", "Using the last IAM policy read after a failed refresh", map[string]any{
				"project": project,
				"age":     time.Since(cached.fetchedAt).String(),
				"error":   err.Error(),
			})
			return cached, nil
		}
		return nil, err
	}
	p.policies[project] = fetched
	return fetched, nil
}

func (p *ProjectIAMRoles) fetch(ctx context.Context, project string) (*projectPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, policyTimeout)
	defer cancel()

	// Version 3 returns conditional bindings with their conditions, so they can
	// be told apart and skipped.
	req := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}
	policy, err := p.svc.Projects.GetIamPolicy(project, req).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("reading IAM policy of project %s: %w", project, err)
	}

	members := map[string]map[string]bool{}
	for _, binding := range policy.Bindings {
		if binding.Condition != nil {
			continue
		}
		if members[binding.Role] == nil {
			members[binding.Role] = map[string]bool{}
		}
		for _, member := range binding.Members {
			members[binding.Role][member] = true
		}
	}
	return &projectPolicy{members: members, fetchedAt: time.Now()}, nil
}

func roleProject(role string) (string, bool) {
	parts := strings.Split(role, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[1] == "" || parts[2] != "roles" || parts[3] == "" {
		return "", false
	}
	return parts[1], true
}
