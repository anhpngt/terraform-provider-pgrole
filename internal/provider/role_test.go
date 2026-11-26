package provider

import (
	"fmt"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The lock tests use role names of their own, so that they do not wait on the
// locks that the resource tests take for role testRole.

func TestLockRole_SameRoleWaits(t *testing.T) {
	t.Parallel()

	unlock := lockRole("lock-test-same")

	acquired := make(chan struct{})
	go func() {
		defer lockRole("lock-test-same")()
		close(acquired)
	}()

	select {
	case <-acquired:
		require.Fail(t, "a second lock on the same role must wait for the first one")
	case <-time.After(50 * time.Millisecond):
	}

	unlock()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		require.Fail(t, "the second lock must succeed after the first one is released")
	}
}

func TestLockRole_DifferentRolesDoNotWait(t *testing.T) {
	t.Parallel()

	defer lockRole("lock-test-a")()

	acquired := make(chan struct{})
	go func() {
		defer lockRole("lock-test-b")()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		assert.Fail(t, "a lock on a different role must not wait")
	}
}

func TestLockRole_RoleNamesAreCaseSensitive(t *testing.T) {
	t.Parallel()

	// PostgreSQL role names are case sensitive when quoted, and the resources
	// always quote them. "App" and "app" are different roles.
	defer lockRole("lock-test-case")()

	acquired := make(chan struct{})
	go func() {
		defer lockRole("LOCK-TEST-CASE")()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		assert.Fail(t, "roles that differ only in case must not share a lock")
	}
}

func TestRoleHelpers_RejectNULBeforeSQL(t *testing.T) {
	t.Parallel()

	const role = testRole + "\x00suffix"
	ctx := t.Context()
	// A nil database makes any attempt to send a statement fail the test.
	assert.ErrorIs(t, execForRole(ctx, nil, role, ""), errRoleNameContainsNUL)
	_, err := roleExists(ctx, nil, role)
	assert.ErrorIs(t, err, errRoleNameContainsNUL)
	assert.ErrorIs(t, undoRoleSetting(ctx, nil, role, ""), errRoleNameContainsNUL)
}

// The tests below need a PostgreSQL server. See helpers_postgres_test.go.

// Terraform creates the settings of one role in parallel when nothing orders
// them, as it does for every user of a for_each. PostgreSQL rejects concurrent
// changes to one role ("tuple concurrently updated", or a duplicate key on
// pg_db_role_setting for a role that has no setting yet), so the provider has
// to apply them one at a time.
func TestSettingsOfOneRoleAppliedInParallel(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	getDB := server.getter(server.username, server.password)

	type create struct {
		name string
		resp *fwresource.CreateResponse
	}

	const roles = 30
	var (
		wg      sync.WaitGroup
		creates []create
	)
	for i := range roles {
		role := fmt.Sprintf("pgrole_test_parallel_%d", i)
		createRole(t, db, role)

		for _, c := range roleSettingCases {
			if c.needsAnon {
				continue
			}

			// Build the request here: the goroutines must not call the
			// test helpers, because a failed require stops only the
			// goroutine that calls it.
			r := c.configured(t, getDB)
			req := fwresource.CreateRequest{Plan: planOf(t, r, c.managed(role))}
			resp := &fwresource.CreateResponse{State: nullState(t, r)}
			creates = append(creates, create{name: c.name + " on " + role, resp: resp})

			ctx := t.Context()
			wg.Go(func() { r.Create(ctx, req, resp) })
		}
	}
	wg.Wait()

	var failures []string
	for _, c := range creates {
		if msg := diagError(c.resp.Diagnostics); msg != "" {
			failures = append(failures, c.name+": "+msg)
		}
	}
	assert.Empty(t, failures, "%d of %d creates failed", len(failures), len(creates))

	// Every setting must be in place: none was lost to a concurrent change of
	// the same role.
	for i := range roles {
		role := fmt.Sprintf("pgrole_test_parallel_%d", i)
		for _, c := range roleSettingCases {
			if c.needsAnon {
				continue
			}
			assert.Equal(t, c.managed(role), readModel(t, c.configured(t, getDB), c.unset(role)), "%s on %s", c.name, role)
		}
	}
}

func TestRoleSettings(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	superuser := server.getter(server.username, server.password)
	anon := hasAnon(t, db)

	// A role that may log in but may not change other roles, to make Delete
	// fail on a role that exists.
	const unprivileged = "pgrole_test_unprivileged"
	createRole(t, db, unprivileged)
	mustExec(t, db, fmt.Sprintf("ALTER ROLE %q LOGIN PASSWORD 'unprivileged';", unprivileged))

	for _, c := range roleSettingCases {
		t.Run(c.name, func(t *testing.T) {
			if c.needsAnon && !anon {
				t.Skip("the anon extension is not loaded on the test server")
			}
			r := c.configured(t, superuser)
			role := "pgrole_test_" + c.name

			t.Run("read reports the setting of an existing role", func(t *testing.T) {
				createRole(t, db, role)
				assert.Equal(t, c.unset(role), readModel(t, r, c.managed(role)), "before the setting is in place")

				mustExec(t, db, c.set(role))
				assert.Equal(t, c.managed(role), readModel(t, r, c.unset(role)), "with the setting in place")
			})

			t.Run("read removes the resource of a dropped role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))
				dropRole(t, db, role)

				assert.Nil(t, readModel(t, r, c.managed(role)), "the resource must be removed from the state")
			})

			t.Run("delete takes the setting off an existing role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))

				requireNoErrors(t, runDelete(t, r, c.managed(role)).Diagnostics)
				assert.Equal(t, c.unset(role), readModel(t, r, c.managed(role)), "after delete")
			})

			t.Run("delete succeeds for a dropped role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))
				dropRole(t, db, role)

				requireNoErrors(t, runDelete(t, r, c.managed(role)).Diagnostics)
			})

			t.Run("delete still fails for an existing role", func(t *testing.T) {
				createRole(t, db, role)
				mustExec(t, db, c.set(role))

				weak := c.configured(t, server.getter(unprivileged, "unprivileged"))
				assert.True(t, runDelete(t, weak, c.managed(role)).Diagnostics.HasError(),
					"delete must fail when the user may not change the role")
				assert.Equal(t, c.managed(role), readModel(t, r, c.managed(role)), "after the failed delete")
			})
		})
	}
}

func TestRoleSettingsQuotedRoleName(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	getDB := server.getter(server.username, server.password)

	const victim = "pgrole_test_v"

	isSuperuser := func(t *testing.T) bool {
		t.Helper()

		var super bool
		require.NoError(t, db.QueryRow("SELECT rolsuper FROM pg_roles WHERE rolname = $1", victim).Scan(&super))
		return super
	}

	for i, c := range roleSettingCases {
		if c.needsAnon {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			prefix := fmt.Sprintf("pgrole_test_q%d", i)
			role := fmt.Sprintf(`%s"; ALTER ROLE %s SUPERUSER; --`, prefix, victim)
			createRole(t, db, victim)
			createRole(t, db, prefix+`\`)
			createRole(t, db, role)
			r := c.configured(t, getDB)

			resp := runCreate(t, r, c.managed(role))
			assert.False(t, isSuperuser(t), "create must not run SQL from the role name")
			requireNoErrors(t, resp.Diagnostics)
			assert.Equal(t, c.managed(role), readModel(t, r, c.unset(role)), "after create")

			requireNoErrors(t, runDelete(t, r, c.managed(role)).Diagnostics)
			assert.False(t, isSuperuser(t), "delete must not run SQL from the role name")
			assert.Equal(t, c.unset(role), readModel(t, r, c.managed(role)), "after delete")
		})
	}
}

func TestAuditLogOptionIsQuoted(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	r := configured(t, NewAuditResource(), server.getter(server.username, server.password))

	const (
		role   = "pgrole_test_audit_value"
		victim = "pgrole_test_audit_victim"
	)
	createRole(t, db, role)
	createRole(t, db, victim)

	option := fmt.Sprintf("none'; ALTER ROLE %s SUPERUSER; --", victim)
	_ = runCreate(t, r, auditModel{Role: role, AuditLogOption: option})

	var super bool
	require.NoError(t, db.QueryRow("SELECT rolsuper FROM pg_roles WHERE rolname = $1", victim).Scan(&super))
	assert.False(t, super, "create must not run SQL from audit_log_option")
}

// TestAccRoleDroppedOutsideTerraform runs the provider under Terraform against
// the test server, for the case that the role is dropped by whatever manages it
// before its settings are removed from the configuration.
func TestAccRoleDroppedOutsideTerraform(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("%s is not set", resource.EnvTfAcc)
	}
	server := newTestServer(t)
	db := server.open(t)

	// Nothing orders the settings, so Terraform applies them in parallel, as
	// it does for the settings of one role in a real configuration.
	const role = "pgrole_test_acc"
	settings := fmt.Sprintf(`
resource "pgrole_audit" "test" {
  role             = %[1]q
  audit_log_option = "all"
}

resource "pgrole_statement_timeout" "test" {
  role    = %[1]q
  timeout = "300s"
}

resource "pgrole_connection_limit" "test" {
  role             = %[1]q
  connection_limit = 5
}
`, role)
	if hasAnon(t, db) {
		settings += fmt.Sprintf(`
resource "pgrole_security_label" "test" {
  role  = %q
  label = "MASKED"
}
`, role)
	}

	create := resource.TestStep{
		PreConfig: func() { createRole(t, db, role) },
		Config:    server.providerConfig() + settings,
		Check:     resource.TestCheckResourceAttr("pgrole_statement_timeout.test", "timeout", "300s"),
	}

	t.Run("settings removed from the configuration", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				create,
				{
					PreConfig: func() { dropRole(t, db, role) },
					Config:    server.providerConfig(),
				},
			},
		})
	})

	t.Run("settings kept in the configuration", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				create,
				{
					// The settings are planned again, and creating them fails
					// because the role is gone.
					PreConfig:   func() { dropRole(t, db, role) },
					Config:      server.providerConfig() + settings,
					ExpectError: regexp.MustCompile(`role "pgrole_test_acc" does not exist`),
				},
			},
		})
	})
}
