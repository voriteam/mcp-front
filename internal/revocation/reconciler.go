// Package revocation reconciles mcp-front's view of who may authenticate against
// Google Workspace account status. A background job polls the Directory API for
// users with active mcp-front state, and for any suspended or deleted account it
// purges stored upstream tokens and sessions and adds the user to the revocation
// set so refresh-token grants are blocked.
//
// Enforcement is intentionally eventual: there is no per-request denylist in the
// token-validation middleware, so an already-issued access token remains valid
// until it expires within its TTL (~1h by default). The reconciler blocks the
// minting of new access tokens (refresh) and removes the user's cached upstream
// credentials and sessions.
package revocation

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/stainless-api/mcp-front/internal/emailutil"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
)

// Store is the subset of storage the reconciler needs.
type Store interface {
	ListUsersWithTokens(ctx context.Context) ([]string, error)
	ListUsersWithSessions(ctx context.Context) ([]string, error)
	ListRevokedUsers(ctx context.Context) ([]string, error)
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	RevokeUserSessions(ctx context.Context, userEmail string) error
	AddRevokedUser(ctx context.Context, userEmail, reason string) error
	RemoveRevokedUser(ctx context.Context, userEmail string) error
}

// StatusLookup resolves a Workspace account's status.
type StatusLookup interface {
	Status(ctx context.Context, email string) (Status, error)
}

// decide is the pure core: given the candidate emails, their resolved statuses,
// and the currently-revoked set, it returns the users to newly revoke and the
// users to restore. Candidates whose status is absent (lookup failed) yield no
// decision and are retried on the next pass.
func decide(candidates []string, statuses map[string]Status, revoked map[string]bool) (toRevoke, toRestore []string) {
	for _, email := range candidates {
		st, ok := statuses[email]
		if !ok {
			continue
		}
		if st.Disabled() {
			if !revoked[email] {
				toRevoke = append(toRevoke, email)
			}
		} else if revoked[email] {
			toRestore = append(toRestore, email)
		}
	}
	return toRevoke, toRestore
}

// Reconciler periodically reconciles the revocation set against Workspace status.
type Reconciler struct {
	store          Store
	directory      StatusLookup
	interval       time.Duration
	allowedDomains []string

	stopCh chan struct{}
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// New creates a Reconciler. allowedDomains, when non-empty, restricts which
// candidate emails are looked up (others are skipped).
func New(store Store, directory StatusLookup, interval time.Duration, allowedDomains []string) *Reconciler {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Reconciler{
		store:          store,
		directory:      directory,
		interval:       interval,
		allowedDomains: allowedDomains,
		stopCh:         make(chan struct{}),
	}
}

// Start launches the background reconciliation loop. It runs one pass
// immediately, then on every interval tick.
func (r *Reconciler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	r.wg.Go(func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		r.runOnce(ctx)
		for {
			select {
			case <-ticker.C:
				r.runOnce(ctx)
			case <-r.stopCh:
				return
			}
		}
	})

	log.LogInfoWithFields("revocation", "Started Workspace revocation reconciler", map[string]any{
		"interval": r.interval.String(),
	})
}

// Stop terminates the loop and waits for the in-flight pass to finish.
func (r *Reconciler) Stop() {
	close(r.stopCh)
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

func (r *Reconciler) runOnce(ctx context.Context) {
	if err := r.reconcile(ctx); err != nil {
		log.LogErrorWithFields("revocation", "Reconciliation pass failed", map[string]any{
			"error": err.Error(),
		})
	}
}

func (r *Reconciler) reconcile(ctx context.Context) error {
	candidates, revoked, err := r.candidates(ctx)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}

	statuses := make(map[string]Status, len(candidates))
	for _, email := range candidates {
		st, err := r.directory.Status(ctx, email)
		if err != nil {
			log.LogWarnWithFields("revocation", "Skipping candidate after directory lookup error", map[string]any{
				"email": email,
				"error": err.Error(),
			})
			continue
		}
		statuses[email] = st
	}

	toRevoke, toRestore := decide(candidates, statuses, revoked)

	for _, email := range toRevoke {
		r.revokeUser(ctx, email, statuses[email])
	}
	for _, email := range toRestore {
		if err := r.store.RemoveRevokedUser(ctx, email); err != nil {
			log.LogErrorWithFields("revocation", "Failed to restore re-enabled user", map[string]any{
				"email": email,
				"error": err.Error(),
			})
			continue
		}
		log.LogInfoWithFields("revocation", "Restored re-enabled Workspace user", map[string]any{
			"email": email,
		})
	}

	return nil
}

// candidates returns the sorted, deduplicated, domain-filtered set of emails to
// check, along with the current revoked set as a membership map.
func (r *Reconciler) candidates(ctx context.Context) ([]string, map[string]bool, error) {
	withTokens, err := r.store.ListUsersWithTokens(ctx)
	if err != nil {
		return nil, nil, err
	}
	withSessions, err := r.store.ListUsersWithSessions(ctx)
	if err != nil {
		return nil, nil, err
	}
	revokedList, err := r.store.ListRevokedUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	revoked := make(map[string]bool, len(revokedList))
	for _, email := range revokedList {
		revoked[email] = true
	}

	seen := make(map[string]struct{})
	var candidates []string
	add := func(emails []string) {
		for _, email := range emails {
			if email == "" {
				continue
			}
			if _, ok := seen[email]; ok {
				continue
			}
			if !r.eligible(email) {
				continue
			}
			seen[email] = struct{}{}
			candidates = append(candidates, email)
		}
	}
	add(withTokens)
	add(withSessions)
	add(revokedList)

	slices.Sort(candidates)
	return candidates, revoked, nil
}

// eligible filters out emails that should never be checked: the reserved
// service-auth domain (service accounts), and any domain outside the configured
// allowlist.
func (r *Reconciler) eligible(email string) bool {
	domain := emailutil.ExtractDomain(email)
	if domain == "" || servicecontext.IsReservedDomain(domain) {
		return false
	}
	if len(r.allowedDomains) > 0 && !slices.Contains(r.allowedDomains, domain) {
		return false
	}
	return true
}

func (r *Reconciler) revokeUser(ctx context.Context, email string, status Status) {
	services, err := r.store.ListUserServices(ctx, email)
	if err != nil {
		log.LogErrorWithFields("revocation", "Failed to list services for revoked user", map[string]any{
			"email": email,
			"error": err.Error(),
		})
		return
	}
	for _, service := range services {
		if err := r.store.DeleteUserToken(ctx, email, service); err != nil {
			log.LogErrorWithFields("revocation", "Failed to delete stored token", map[string]any{
				"email":   email,
				"service": service,
				"error":   err.Error(),
			})
			return
		}
	}

	if err := r.store.RevokeUserSessions(ctx, email); err != nil {
		log.LogErrorWithFields("revocation", "Failed to revoke sessions", map[string]any{
			"email": email,
			"error": err.Error(),
		})
		return
	}

	if err := r.store.AddRevokedUser(ctx, email, status.String()); err != nil {
		log.LogErrorWithFields("revocation", "Failed to record revoked user", map[string]any{
			"email": email,
			"error": err.Error(),
		})
		return
	}

	log.LogInfoWithFields("revocation", "Revoked disabled Workspace user", map[string]any{
		"email":    email,
		"status":   status.String(),
		"services": len(services),
	})
}
