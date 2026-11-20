package provider

import (
	"fmt"
	"sync"
	"testing"
)

// Terraform creates the settings of one role in parallel when nothing orders them, as it does for
// every user of a for_each. PostgreSQL rejects concurrent changes to one role ("tuple concurrently
// updated", or a duplicate key on pg_db_role_setting for a role that has no setting yet), so the
// provider has to apply them one at a time.
func TestSettingsOfOneRoleAppliedInParallel(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	getDB := server.getter(server.username, server.password)

	const roles = 30
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []string
	)
	for i := range roles {
		role := fmt.Sprintf("pgrole_test_parallel_%d", i)
		createRole(t, db, role)

		for _, c := range roleSettingCases {
			if c.needsAnon {
				continue
			}
			r := c.configured(t, getDB)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if msg := createResource(r, c.managed(role)); msg != "" {
					mu.Lock()
					failures = append(failures, c.name+" on "+role+": "+msg)
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()

	if len(failures) > 0 {
		t.Errorf("%d of %d creates failed, for example: %s", len(failures), roles*(len(roleSettingCases)-1), failures[0])
	}

	// Every setting must be in place: none was lost to a concurrent change of the same role.
	for i := range roles {
		role := fmt.Sprintf("pgrole_test_parallel_%d", i)
		for _, c := range roleSettingCases {
			if c.needsAnon {
				continue
			}
			if got, want := read(t, c.configured(t, getDB), c.unset(role)), c.managed(role); got != want {
				t.Errorf("%s: got %+v, want %+v", c.name, got, want)
			}
		}
	}
}
