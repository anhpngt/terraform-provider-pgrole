package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testRoleOID is the oid that the mock database gives role testRole.
	testRoleOID = int64(16384)
	// testDatabase is the database that the mock database is.
	testDatabase = "postgres"

	removeLabelSQL = `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`
	revokeSummary  = "Failed to revoke the masking privileges of the role"
)

// labelWithRevoke is the state of a label that revokes on destroy.
var labelWithRevoke = securityLabelModel{Role: testRole, Label: "MASKED", RevokeOnDestroy: types.BoolValue(true)}

// whatAnonGrants is what PostgreSQL Anonymizer gives a masked role in one database, with the
// objects owned by role "owner".
var whatAnonGrants = []maskingPrivilege{
	{kind: maskingSchema, schema: "anon", owner: "owner"},
	{kind: maskingSequences, schema: "anon", owner: "owner"},
	{kind: maskingTables, schema: "anon", owner: "owner"},
	{kind: maskingSchema, schema: "mask", owner: "owner"},
	{kind: maskingTables, schema: "mask", owner: "owner"},
}

func expectRoleOID(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(exact(sqlRoleOID)).WithArgs(testRole).
		WillReturnRows(sqlmock.NewRows([]string{"oid"}).AddRow(testRoleOID))
}

// expectPrivilegeDatabases makes the mock report the connectable databases where the role holds
// privileges, acquire the advisory lock, and report the current database.
func expectPrivilegeDatabases(mock sqlmock.Sqlmock, databases ...string) {
	dbs := make([]rolePrivilegeDatabase, len(databases))
	for i, name := range databases {
		dbs[i] = rolePrivilegeDatabase{name: name, canConnect: true}
	}
	expectPrivilegeDatabaseRows(mock, dbs...)
}

func expectPrivilegeDatabaseRows(mock sqlmock.Sqlmock, databases ...rolePrivilegeDatabase) {
	rows := sqlmock.NewRows([]string{"datname", "has_database_privilege"})
	hasConnectable := false
	for _, d := range databases {
		rows.AddRow(d.name, d.canConnect)
		if d.canConnect {
			hasConnectable = true
		}
	}
	mock.ExpectQuery(exact(sqlRolePrivilegeDatabases)).WithArgs(testRoleOID).WillReturnRows(rows)
	if hasConnectable {
		mock.ExpectExec(exact(sqlAcquireRevokeLock)).WithArgs(revokeAdvisoryLockKey).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(exact(sqlCurrentDatabase)).
			WillReturnRows(sqlmock.NewRows([]string{"current_database"}).AddRow(testDatabase))
	}
}

func expectAdvisoryUnlock(mock sqlmock.Sqlmock) {
	mock.ExpectExec(exact(sqlReleaseRevokeLock)).WithArgs(revokeAdvisoryLockKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectMaskingPrivileges(mock sqlmock.Sqlmock, held ...maskingPrivilege) {
	rows := sqlmock.NewRows([]string{"kind", "schema", "owner"})
	for _, p := range held {
		rows.AddRow(p.kind, p.schema, p.owner)
	}
	mock.ExpectQuery(exact(sqlMaskingPrivileges)).WithArgs(testRoleOID).WillReturnRows(rows)
}

// expectOwnerPrivilegeState makes the mock report the provider user's privilege state for role
// "owner", which owns the objects of whatAnonGrants.
func expectOwnerPrivilegeState(mock sqlmock.Sqlmock, hasUsage, canInherit, hasSelfGranted bool) {
	mock.ExpectQuery(exact(sqlRolePrivilegeState)).WithArgs("owner").
		WillReturnRows(sqlmock.NewRows([]string{"has_usage", "rolinherit", "has_self_granted"}).
			AddRow(hasUsage, canInherit, hasSelfGranted))
}

// expectHasPrivilegesOfOwner makes the mock say whether the provider's user has the privileges of
// role "owner" after a GRANT.
func expectHasPrivilegesOfOwner(mock sqlmock.Sqlmock, has bool) {
	mock.ExpectQuery(exact(sqlHasPrivilegesOfRole)).WithArgs("owner").
		WillReturnRows(sqlmock.NewRows([]string{"pg_has_role"}).AddRow(has))
}

// expectRevokes expects the statements that take back whatAnonGrants, without the transaction
// around them.
func expectRevokes(mock sqlmock.Sqlmock) {
	expectExec(mock, `REVOKE ALL PRIVILEGES ON SCHEMA "anon" FROM "app";`)
	expectExec(mock, `REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA "anon" FROM "app";`)
	expectExec(mock, `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA "anon" FROM "app";`)
	expectExec(mock, `REVOKE ALL PRIVILEGES ON SCHEMA "mask" FROM "app";`)
	expectExec(mock, `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA "mask" FROM "app";`)
}

func TestSecurityLabelResource_RevokeOnDestroyAttribute(t *testing.T) {
	t.Parallel()

	// Optional and without a default: a resource that does not set it holds null, as the
	// resources created before the attribute existed do, so an upgrade plans no change.
	attr, ok := resourceSchema(t, NewSecurityLabelResource()).Attributes["revoke_on_destroy"].(schema.BoolAttribute)
	require.True(t, ok)
	assert.True(t, attr.Optional)
	assert.False(t, attr.Required)
	assert.False(t, attr.Computed)
	assert.Nil(t, attr.Default)
}

func TestMaskingPrivilege_SQLRevoke(t *testing.T) {
	t.Parallel()

	const role = `jane.doe@example.com`
	assert.Equal(t, `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA "mask" FROM "jane.doe@example.com";`,
		maskingPrivilege{kind: maskingTables, schema: "mask"}.sqlRevoke(role))
	assert.Equal(t, `REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA "anon" FROM "jane.doe@example.com";`,
		maskingPrivilege{kind: maskingSequences, schema: "anon"}.sqlRevoke(role))
	assert.Equal(t, `REVOKE ALL PRIVILEGES ON SCHEMA "my ""mask""" FROM "jane.doe@example.com";`,
		maskingPrivilege{kind: maskingSchema, schema: `my "mask"`}.sqlRevoke(role))
}

func TestIsTransient(t *testing.T) {
	t.Parallel()

	assert.True(t, isTransient(&pq.Error{Code: "XX000", Message: "tuple concurrently updated"}))
	assert.True(t, isTransient(fmt.Errorf("wrapped: %w", &pq.Error{Code: "40P01", Message: "deadlock detected"})))
	assert.True(t, isTransient(&pq.Error{Code: "55P03", Message: "canceling statement due to lock timeout"}))
	assert.False(t, isTransient(&pq.Error{Code: "42501", Message: "permission denied"}))
	assert.False(t, isTransient(errors.New("tuple concurrently updated")), "only errors of the server count")
}

func TestSecurityLabelResource_DeleteWithRevoke(t *testing.T) {
	t.Parallel()

	t.Run("not asked for", func(t *testing.T) {
		t.Parallel()

		// Without the attribute, or with false, Delete removes the label and nothing else, as it
		// always did.
		for _, revoke := range []types.Bool{types.BoolNull(), types.BoolValue(false)} {
			r, mock := newMockedResource(t, NewSecurityLabelResource)
			expectExec(mock, removeLabelSQL)
			mock.ExpectClose()

			model := securityLabelModel{Role: testRole, Label: "MASKED", RevokeOnDestroy: revoke}
			requireNoErrors(t, runDelete(t, r, model).Diagnostics)
		}
	})

	t.Run("role is gone", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExecError(mock, removeLabelSQL, errors.New(`role "app" does not exist`))
		expectRoleCheck(mock, false)
		mock.ExpectQuery(exact(sqlRoleOID)).WithArgs(testRole).WillReturnRows(sqlmock.NewRows([]string{"oid"}))
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("role holds no privileges", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("privileges outside the masking schemas only", func(t *testing.T) {
		t.Parallel()

		// They are not from PostgreSQL Anonymizer. Nothing is revoked.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("revokes after the label, with the privileges of the owner", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		// The user has the privileges of the owner already: no membership is taken.
		expectOwnerPrivilegeState(mock, true, true, false)
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("takes a membership for the time of the revoke", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExec(mock, `GRANT "owner" TO CURRENT_USER;`)
		expectHasPrivilegesOfOwner(mock, true)
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock)
		expectExec(mock, `REVOKE "owner" FROM CURRENT_USER;`)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("membership cannot be taken", func(t *testing.T) {
		t.Parallel()

		// As on PostgreSQL 16 without ADMIN OPTION. Nothing is revoked, and the destroy fails so
		// that the next apply tries again.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExecError(mock, `GRANT "owner" TO CURRENT_USER;`, &pq.Error{Code: "42501", Message: `permission denied to grant role "owner"`})
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), `permission denied to grant role "owner"`)
		assert.Contains(t, diagError(resp.Diagnostics), "ADMIN OPTION")
		assert.Contains(t, diagError(resp.Diagnostics), `database "postgres"`)
	})

	t.Run("NOINHERIT user does not grant or revoke existing membership", func(t *testing.T) {
		t.Parallel()

		// A NOINHERIT user cannot inherit privileges from a GRANT, and revoking afterwards would
		// remove a membership it already held. Neither GRANT nor REVOKE may run.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, false, false)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), "NOINHERIT")
	})

	t.Run("pre-existing self-granted non-inheriting membership is not revoked", func(t *testing.T) {
		t.Parallel()

		// On PostgreSQL 16+, if CURRENT_USER already holds a self-granted membership with
		// INHERIT FALSE, GRANT would not change it and REVOKE would remove it.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, true)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), "already a member of the role without inheriting")
	})

	t.Run("membership without inherited privileges after GRANT", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExec(mock, `GRANT "owner" TO CURRENT_USER;`)
		expectHasPrivilegesOfOwner(mock, false)
		expectExec(mock, `REVOKE "owner" FROM CURRENT_USER;`)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), "does not inherit its privileges")
	})

	t.Run("non-permission server error on GRANT is not blamed on ADMIN OPTION", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExecError(mock, `GRANT "owner" TO CURRENT_USER;`, &pq.Error{Code: "0LP01", Message: `role "app" cannot be a member of itself`})
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), "cannot be a member of itself")
		assert.NotContains(t, diagError(resp.Diagnostics), "ADMIN OPTION")
	})

	t.Run("interrupted GRANT that committed on server is cleaned up", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExecError(mock, `GRANT "owner" TO CURRENT_USER;`, context.Canceled)
		expectHasPrivilegesOfOwner(mock, true)
		expectExec(mock, `REVOKE "owner" FROM CURRENT_USER;`)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), context.Canceled.Error())
		assert.NotContains(t, diagError(resp.Diagnostics), "ADMIN OPTION")
	})

	t.Run("interrupted GRANT that did not commit is not revoked", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExecError(mock, `GRANT "owner" TO CURRENT_USER;`, context.Canceled)
		expectHasPrivilegesOfOwner(mock, false)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), context.Canceled.Error())
		assert.NotContains(t, diagError(resp.Diagnostics), "ADMIN OPTION")
	})

	t.Run("skips database without CONNECT privilege with a warning", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabaseRows(mock,
			rolePrivilegeDatabase{name: "restricted", canConnect: false},
			rolePrivilegeDatabase{name: testDatabase, canConnect: true},
		)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, true, true, false)
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		requireNoErrors(t, resp.Diagnostics)
		require.Equal(t, 1, resp.Diagnostics.WarningsCount())
		assert.Contains(t, resp.Diagnostics[0].Detail(), `database "restricted"`)
	})

	t.Run("only unconnectable databases warns without taking lock", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabaseRows(mock,
			rolePrivilegeDatabase{name: "restricted", canConnect: false},
		)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		requireNoErrors(t, resp.Diagnostics)
		require.Equal(t, 1, resp.Diagnostics.WarningsCount())
		assert.Contains(t, resp.Diagnostics[0].Detail(), `database "restricted"`)
	})

	t.Run("a concurrent change is tried again", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, true, true, false)
		mock.ExpectBegin()
		expectExecError(mock, `REVOKE ALL PRIVILEGES ON SCHEMA "anon" FROM "app";`, &pq.Error{Code: "XX000", Message: "tuple concurrently updated"})
		mock.ExpectRollback()
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock)
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, labelWithRevoke).Diagnostics)
	})

	t.Run("revoke fails", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, true, true, false)
		mock.ExpectBegin()
		expectExecError(mock, `REVOKE ALL PRIVILEGES ON SCHEMA "anon" FROM "app";`, &pq.Error{Code: "42501", Message: "permission denied for schema anon"})
		mock.ExpectRollback()
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), "permission denied for schema anon")
	})

	t.Run("privileges are left", func(t *testing.T) {
		t.Parallel()

		// A REVOKE only warns about a privilege that another role granted. The check afterwards
		// finds it.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, true, true, false)
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock, maskingPrivilege{kind: maskingTables, schema: "mask", owner: "owner"})
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), `still holds privileges on tables in schema "mask"`)
	})

	t.Run("membership cannot be taken back", func(t *testing.T) {
		t.Parallel()

		// The privileges are revoked, but the provider's user is left with more than it had.
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		expectPrivilegeDatabases(mock, testDatabase)
		expectMaskingPrivileges(mock, whatAnonGrants...)
		expectOwnerPrivilegeState(mock, false, true, false)
		expectExec(mock, `GRANT "owner" TO CURRENT_USER;`)
		expectHasPrivilegesOfOwner(mock, true)
		mock.ExpectBegin()
		expectRevokes(mock)
		mock.ExpectCommit()
		expectMaskingPrivileges(mock)
		expectExecError(mock, `REVOKE "owner" FROM CURRENT_USER;`, errors.New("connection reset"))
		expectAdvisoryUnlock(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, labelWithRevoke)
		assertError(t, resp.Diagnostics, revokeSummary)
		assert.Contains(t, diagError(resp.Diagnostics), `failed to take back the membership in role "owner"`)
	})

	t.Run("catalog query fails", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, removeLabelSQL)
		expectRoleOID(mock)
		mock.ExpectQuery(exact(sqlRolePrivilegeDatabases)).WithArgs(testRoleOID).WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		assertError(t, runDelete(t, r, labelWithRevoke).Diagnostics, revokeSummary)
	})
}

func TestMaskingRevokeSQLGuards(t *testing.T) {
	t.Parallel()

	assert.Contains(t, sqlMaskingPrivileges, "pg_extension", "must require the anon extension before touching anon/mask schemas")
	assert.Contains(t, sqlMaskingPrivileges, "extname = 'anon'")
	assert.Contains(t, sqlRolePrivilegeDatabases, "d.datallowconn")
	assert.Contains(t, sqlRolePrivilegeDatabases, "has_database_privilege(d.oid, 'CONNECT')")
}

// The tests below need a PostgreSQL server. See helpers_postgres_test.go.
//
// Their roles and databases copy what dynamic masking leaves behind: privileges on two schemas, in
// more than one database, granted by a role that the provider's user is not a member of.
const (
	testOwner       = "pgrole_test_owner"       // owns the schemas and grants the privileges; not a superuser
	testProvisioner = "pgrole_test_provisioner" // the provider's user: CREATEROLE, not a member of the owner
	testNobody      = "pgrole_test_nobody"      // may log in and nothing else
)

var (
	testAnonDatabases  = []string{"pgrole_test_db1", "pgrole_test_db2"}
	testNoAnonDatabase = "pgrole_test_no_anon"
	testDatabases      = append(append([]string(nil), testAnonDatabases...), testNoAnonDatabase)
)

// A maskingLayout holds the connections of a test to the layout above.
type maskingLayout struct {
	server    testServer
	superuser *sql.DB
	// owner is the connection of the owner to each test database.
	owner map[string]*sql.DB
	// adminOnly is true on PostgreSQL 16 and newer, where CREATEROLE alone no longer lets a user
	// grant itself any role. The provisioner then has ADMIN OPTION on the owner, without its
	// privileges.
	adminOnly bool
}

func newMaskingLayout(t *testing.T, server testServer, db *sql.DB) maskingLayout {
	t.Helper()

	var version int
	require.NoError(t, db.QueryRow("SELECT current_setting('server_version_num')::int;").Scan(&version))
	l := maskingLayout{server: server, superuser: db, owner: map[string]*sql.DB{}, adminOnly: version >= 160000}

	drop := func() {
		for _, database := range testDatabases {
			mustExec(t, db, fmt.Sprintf("DROP DATABASE IF EXISTS %q;", database))
		}
		for _, role := range []string{testOwner, testProvisioner, testNobody} {
			dropRole(t, db, role)
		}
	}
	drop()
	// Registered before any connection to the test databases is opened, so that it runs once
	// they are closed: a database in use cannot be dropped.
	t.Cleanup(drop)

	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'owner';", testOwner))
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'provisioner' CREATEROLE;", testProvisioner))
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'nobody';", testNobody))
	if l.adminOnly {
		mustExec(t, db, fmt.Sprintf("GRANT %q TO %q WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;", testOwner, testProvisioner))
	}
	return l
}

// setupTestDatabases creates two databases with the anon extension and one without it that still
// has a "mask" schema, so tests verify both revoking and leaving non-anon databases alone.
func (l *maskingLayout) setupTestDatabases(t *testing.T) {
	t.Helper()

	mustExec(t, l.superuser, fmt.Sprintf("ALTER ROLE %q SUPERUSER;", testOwner))
	defer mustExec(t, l.superuser, fmt.Sprintf("ALTER ROLE %q NOSUPERUSER;", testOwner))

	for _, database := range testAnonDatabases {
		mustExec(t, l.superuser, fmt.Sprintf("CREATE DATABASE %q OWNER %q TEMPLATE template0;", database, testOwner))
		conn := l.open(t, testOwner, "owner", database)
		mustExec(t, conn, "CREATE EXTENSION anon CASCADE;")
		mustExec(t, conn, "CREATE SCHEMA app;")
		mustExec(t, conn, "CREATE TABLE app.users (id int);")
		mustExec(t, conn, "CREATE SCHEMA IF NOT EXISTS mask;")
		mustExec(t, conn, "CREATE VIEW mask.users AS SELECT id FROM app.users;")
		l.owner[database] = conn
	}
	mustExec(t, l.superuser, fmt.Sprintf("ALTER ROLE %q NOSUPERUSER;", testOwner))

	mustExec(t, l.superuser, fmt.Sprintf("CREATE DATABASE %q OWNER %q TEMPLATE template0;", testNoAnonDatabase, testOwner))
	noAnon := l.open(t, testOwner, "owner", testNoAnonDatabase)
	mustExec(t, noAnon, "CREATE SCHEMA mask;")
	mustExec(t, noAnon, "CREATE TABLE mask.items (id int);")
	l.owner[testNoAnonDatabase] = noAnon
}

// open connects to one of the test databases, until the test ends.
func (l maskingLayout) open(t *testing.T, username, password, database string) *sql.DB {
	t.Helper()

	db, err := l.server.getter(username, password)(withDatabase(t.Context(), database))
	require.NoError(t, err, "connect to %s as %s", database, username)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// maskedRole creates a role that holds what PostgreSQL Anonymizer gives a masked role in every
// anon test database, plus privileges that have nothing to do with masking: on another schema,
// on a database without the anon extension that happens to have a "mask" schema, and on a database.
func (l maskingLayout) maskedRole(t *testing.T, role string) {
	t.Helper()

	createRole(t, l.superuser, role)
	for _, database := range testAnonDatabases {
		conn := l.owner[database]
		mustExec(t, conn, fmt.Sprintf("GRANT USAGE ON SCHEMA anon, mask TO %q;", role))
		mustExec(t, conn, fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA anon, mask TO %q;", role))
		mustExec(t, conn, fmt.Sprintf("GRANT SELECT ON ALL SEQUENCES IN SCHEMA anon TO %q;", role))

		mustExec(t, conn, fmt.Sprintf("GRANT USAGE ON SCHEMA app TO %q;", role))
		mustExec(t, conn, fmt.Sprintf("GRANT SELECT ON app.users TO %q;", role))
	}
	noAnon := l.owner[testNoAnonDatabase]
	mustExec(t, noAnon, fmt.Sprintf("GRANT USAGE ON SCHEMA mask TO %q;", role))
	mustExec(t, noAnon, fmt.Sprintf("GRANT SELECT ON mask.items TO %q;", role))
	mustExec(t, l.owner[testAnonDatabases[0]], fmt.Sprintf("GRANT CONNECT ON DATABASE %q TO %q;", testAnonDatabases[0], role))

	// Registered after createRole, so it runs first: once the role holds nothing in the test
	// databases, it can be dropped.
	t.Cleanup(func() { l.dropOwned(t, role, testDatabases...) })
}

// dropOwned takes everything a role holds in the given databases away, as the superuser. It is for
// cleanup functions, so it does not use the context of the test, which is canceled by then.
func (l maskingLayout) dropOwned(t *testing.T, role string, databases ...string) {
	t.Helper()

	// The test may have dropped the role itself.
	var exists bool
	if err := l.superuser.QueryRow(roleExistsSQL, role).Scan(&exists); !assert.NoError(t, err) || !exists {
		return
	}

	for _, database := range databases {
		conn, err := l.server.getter(l.server.username, l.server.password)(withDatabase(context.Background(), database))
		if !assert.NoError(t, err, "connect to %s", database) {
			continue
		}
		_, err = conn.Exec(fmt.Sprintf("DROP OWNED BY %s;", pq.QuoteIdentifier(role)))
		assert.NoError(t, err, "drop what %s holds in %s", role, database)
		_ = conn.Close()
	}
}

// privileges counts the privileges of a role per database ("" for shared objects), such as
// ":1, pgrole_test_db1:7". It is empty when PostgreSQL would let the role be dropped.
func (l maskingLayout) privileges(t *testing.T, role string) string {
	t.Helper()

	counts, err := queryStrings(t.Context(), l.superuser, `SELECT COALESCE(d.datname, '') || ':' || count(*)
FROM pg_shdepend s
JOIN pg_roles r ON r.oid = s.refobjid
LEFT JOIN pg_database d ON d.oid = s.dbid
WHERE s.refclassid = 'pg_authid'::regclass AND r.rolname = $1
GROUP BY d.datname
ORDER BY 1;`, role)
	require.NoError(t, err, "privileges of %s", role)
	return strings.Join(counts, ", ")
}

// roleMemberships lists the memberships of a role, with who granted each.
func (l maskingLayout) roleMemberships(t *testing.T, role string) string {
	t.Helper()

	roles, err := queryStrings(t.Context(), l.superuser, `SELECT g.rolname || ' by ' || pg_get_userbyid(m.grantor)
FROM pg_auth_members m
JOIN pg_roles g ON g.oid = m.roleid
JOIN pg_roles r ON r.oid = m.member
WHERE r.rolname = $1
ORDER BY 1;`, role)
	require.NoError(t, err, "memberships of %s", role)
	return strings.Join(roles, ", ")
}

// provisionerMemberships lists the memberships of the provider's user, with who granted each.
func (l maskingLayout) provisionerMemberships(t *testing.T) string {
	t.Helper()
	return l.roleMemberships(t, testProvisioner)
}

// revokeAs runs the revoke the way Delete does, as the given user. It does not go through Delete,
// whose first statement needs the anon extension.
func (l maskingLayout) revokeAs(t *testing.T, username, password, role string) ([]string, error) {
	t.Helper()

	getDB := l.server.getter(username, password)
	db, err := getDB(t.Context())
	require.NoError(t, err, "connect as %s", username)
	defer db.Close()

	return (&securityLabelResource{getDB: getDB}).revokeMaskingPrivileges(t.Context(), db, role)
}

const (
	// What survives after revoking masking privileges: CONNECT on pgrole_test_db1, the app schema
	// + app.users in each anon database, and the unrelated mask schema + mask.items in the
	// non-anon database.
	privilegesWithoutMasking = ":1, pgrole_test_db1:2, pgrole_test_db2:2, pgrole_test_no_anon:2"
)

func TestActAs_Postgres(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	l := newMaskingLayout(t, server, db)

	t.Run("NOINHERIT user keeps its pre-existing membership", func(t *testing.T) {
		const noInheritUser = "pgrole_test_noinherit"
		dropRole(t, db, noInheritUser)
		mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'noinherit' NOINHERIT CREATEROLE;", noInheritUser))
		t.Cleanup(func() { dropRole(t, db, noInheritUser) })
		mustExec(t, db, fmt.Sprintf("GRANT %q TO %q;", testOwner, noInheritUser))

		before := l.roleMemberships(t, noInheritUser)
		conn := l.open(t, noInheritUser, "noinherit", "postgres")
		able, granted, err := actAs(t.Context(), conn, conn, testOwner)
		require.NoError(t, err)
		assert.False(t, able.can)
		assert.False(t, granted)
		assert.Contains(t, able.reason, "NOINHERIT")
		assert.Equal(t, before, l.roleMemberships(t, noInheritUser), "existing membership must be untouched")
	})

	t.Run("CREATEROLE alone is not enough on PostgreSQL 16 and newer", func(t *testing.T) {
		if !l.adminOnly {
			t.Skip("before PostgreSQL 16, CREATEROLE lets a user grant itself any role")
		}
		mustExec(t, db, fmt.Sprintf("REVOKE %q FROM %q;", testOwner, testProvisioner))
		defer mustExec(t, db, fmt.Sprintf("GRANT %q TO %q WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;", testOwner, testProvisioner))

		conn := l.open(t, testProvisioner, "provisioner", "postgres")
		able, granted, err := actAs(t.Context(), conn, conn, testOwner)
		require.NoError(t, err)
		assert.False(t, able.can)
		assert.False(t, granted)
		assert.NotEmpty(t, able.reason)
	})
}

func TestRevokeMaskingPrivileges(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	if !hasAnon(t, db) {
		t.Skip("the anon extension is not loaded on the test server")
	}
	l := newMaskingLayout(t, server, db)
	l.setupTestDatabases(t)

	t.Run("revokes in every anon database and keeps the other privileges", func(t *testing.T) {
		const role = "pgrole_test_masked"
		l.maskedRole(t, role)
		memberships := l.provisionerMemberships(t)
		before := l.privileges(t, role)
		require.NotEqual(t, privilegesWithoutMasking, before, "before the revoke")

		warnings, err := l.revokeAs(t, testProvisioner, "provisioner", role)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		assert.Equal(t, privilegesWithoutMasking, l.privileges(t, role))
		assert.Equal(t, memberships, l.provisionerMemberships(t), "the provider's user must keep no membership")

		// A second run has nothing to do.
		warnings, err = l.revokeAs(t, testProvisioner, "provisioner", role)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		assert.Equal(t, privilegesWithoutMasking, l.privileges(t, role))
	})

	t.Run("does nothing for a role without privileges, or for a role that is gone", func(t *testing.T) {
		const role = "pgrole_test_plain"
		createRole(t, db, role)
		memberships := l.provisionerMemberships(t)

		warnings, err := l.revokeAs(t, testProvisioner, "provisioner", role)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		dropRole(t, db, role)
		warnings, err = l.revokeAs(t, testProvisioner, "provisioner", role)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		assert.Equal(t, memberships, l.provisionerMemberships(t))
	})

	t.Run("fails when the user cannot act as the owner", func(t *testing.T) {
		const role = "pgrole_test_stuck"
		l.maskedRole(t, role)
		before := l.privileges(t, role)

		_, err := l.revokeAs(t, testNobody, "nobody", role)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not get")
		assert.Contains(t, err.Error(), `database "pgrole_test_db1"`)
		assert.Contains(t, err.Error(), `database "pgrole_test_db2"`)
		assert.Equal(t, before, l.privileges(t, role), "nothing must be revoked")

		// A superuser needs no membership.
		warnings, err := l.revokeAs(t, server.username, server.password, role)
		require.NoError(t, err)
		assert.Empty(t, warnings)
		assert.Equal(t, privilegesWithoutMasking, l.privileges(t, role))
	})

	t.Run("CREATEROLE alone is not enough on PostgreSQL 16 and newer", func(t *testing.T) {
		if !l.adminOnly {
			t.Skip("before PostgreSQL 16, CREATEROLE lets a user grant itself any role")
		}
		const role = "pgrole_test_no_admin"
		l.maskedRole(t, role)
		before := l.privileges(t, role)

		mustExec(t, db, fmt.Sprintf("REVOKE %q FROM %q;", testOwner, testProvisioner))
		defer mustExec(t, db, fmt.Sprintf("GRANT %q TO %q WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;", testOwner, testProvisioner))

		_, err := l.revokeAs(t, testProvisioner, "provisioner", role)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ADMIN OPTION")
		assert.Equal(t, before, l.privileges(t, role), "nothing must be revoked")
	})

	t.Run("several roles at once", func(t *testing.T) {
		const count = 8
		roles := make([]string, count)
		for i := range roles {
			roles[i] = fmt.Sprintf("pgrole_test_masked_%d", i)
			l.maskedRole(t, roles[i])
		}
		memberships := l.provisionerMemberships(t)

		getDB := server.getter(testProvisioner, "provisioner")
		var wg sync.WaitGroup
		errs := make([]error, count)
		for i, role := range roles {
			ctx := t.Context()
			wg.Go(func() {
				db, err := getDB(ctx)
				if err != nil {
					errs[i] = err
					return
				}
				defer db.Close()
				_, errs[i] = (&securityLabelResource{getDB: getDB}).revokeMaskingPrivileges(ctx, db, role)
			})
		}
		wg.Wait()

		for i, role := range roles {
			assert.NoError(t, errs[i], role)
			assert.Equal(t, privilegesWithoutMasking, l.privileges(t, role), role)
		}
		assert.Equal(t, memberships, l.provisionerMemberships(t), "the provider's user must keep no membership")
	})
}

// A maskedDatabase is a database where PostgreSQL Anonymizer runs dynamic masking for real.
type maskedDatabase struct {
	name string
	// owner is the connection of the role that started dynamic masking, which is the role
	// that PostgreSQL Anonymizer grants privileges as.
	owner *sql.DB
}

// newMaskedDatabase starts dynamic masking in a new database, or skips the test when the server
// does not have the anon extension.
//
// roles are the roles that the test gives the MASKED label. One that an earlier, failed run left
// behind still has its label, and would get privileges in the new database: they are dropped
// here, while no database holds anything for them.
func (l maskingLayout) newMaskedDatabase(t *testing.T, roles ...string) maskedDatabase {
	t.Helper()

	if !hasAnon(t, l.superuser) {
		t.Skip("the anon extension is not loaded on the test server")
	}

	const name = "pgrole_test_masked_db"
	drop := func() { mustExec(t, l.superuser, fmt.Sprintf("DROP DATABASE IF EXISTS %q;", name)) }
	drop()
	t.Cleanup(drop)
	for _, role := range roles {
		dropRole(t, l.superuser, role)
	}
	mustExec(t, l.superuser, fmt.Sprintf("CREATE DATABASE %q OWNER %q TEMPLATE template0;", name, testOwner))

	// Starting dynamic masking takes a superuser. The owner is an ordinary role again
	// afterwards, and PostgreSQL Anonymizer keeps granting in its name. It keeps CREATEROLE,
	// which PostgreSQL Anonymizer needs to set the search_path of the masked roles.
	mustExec(t, l.superuser, fmt.Sprintf("ALTER ROLE %q SUPERUSER;", testOwner))
	owner := l.open(t, testOwner, "owner", name)
	mustExec(t, owner, "CREATE EXTENSION anon CASCADE;")
	mustExec(t, owner, "CREATE TABLE public.people (id int, name text);")
	mustExec(t, owner, "SELECT anon.start_dynamic_masking();")
	mustExec(t, l.superuser, fmt.Sprintf("ALTER ROLE %q NOSUPERUSER CREATEROLE;", testOwner))

	return maskedDatabase{name: name, owner: owner}
}

// touchedTables numbers the tables that touchTables creates.
var touchedTables atomic.Int64

// touchTables creates a table, which makes PostgreSQL Anonymizer grant every role with the MASKED
// label its privileges again.
func (d maskedDatabase) touchTables(t *testing.T) {
	t.Helper()

	mustExec(t, d.owner, fmt.Sprintf("CREATE TABLE public.touched_%d (id int);", touchedTables.Add(1)))
}

func TestSecurityLabelRevokeOnDestroy_DynamicMasking(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	l := newMaskingLayout(t, server, db)

	const (
		stays      = "pgrole_test_stays"       // a masked role that stays, to see that it is left alone
		leftBehind = "pgrole_test_left_behind" // loses its label without revoke_on_destroy
		leaver     = "pgrole_test_leaver"      // loses its label with revoke_on_destroy
	)
	masked := l.newMaskedDatabase(t, stays, leftBehind, leaver)

	provisioner := configured(t, NewSecurityLabelResource(), server.getter(testProvisioner, "provisioner"))
	label := func(role string, revoke types.Bool) securityLabelModel {
		return securityLabelModel{Role: role, Label: "MASKED", RevokeOnDestroy: revoke}
	}

	createRole(t, db, stays)
	t.Cleanup(func() { l.dropOwned(t, stays, masked.name) })
	requireNoErrors(t, runCreate(t, provisioner, label(stays, types.BoolNull())).Diagnostics)

	t.Run("without revoke_on_destroy the role cannot be dropped", func(t *testing.T) {
		const role = leftBehind
		createRole(t, db, role)
		t.Cleanup(func() { l.dropOwned(t, role, masked.name) })
		requireNoErrors(t, runCreate(t, provisioner, label(role, types.BoolNull())).Diagnostics)
		masked.touchTables(t)
		require.NotEmpty(t, l.privileges(t, role), "dynamic masking must have granted the role its privileges")

		requireNoErrors(t, runDelete(t, provisioner, label(role, types.BoolNull())).Diagnostics)
		assert.NotEmpty(t, l.privileges(t, role), "the privileges stay when the label is removed")
		_, err := db.Exec(fmt.Sprintf("DROP ROLE %q;", role))
		assert.ErrorContains(t, err, "cannot be dropped because some objects depend on it")
	})

	t.Run("with revoke_on_destroy the role can be dropped", func(t *testing.T) {
		const role = leaver
		createRole(t, db, role)
		t.Cleanup(func() { l.dropOwned(t, role, masked.name) })
		requireNoErrors(t, runCreate(t, provisioner, label(role, types.BoolValue(true))).Diagnostics)
		masked.touchTables(t)
		require.NotEmpty(t, l.privileges(t, role), "dynamic masking must have granted the role its privileges")
		memberships := l.provisionerMemberships(t)

		requireNoErrors(t, runDelete(t, provisioner, label(role, types.BoolValue(true))).Diagnostics)
		assert.Empty(t, l.privileges(t, role))
		assert.Equal(t, memberships, l.provisionerMemberships(t), "the provider's user must keep no membership")

		// The next change of a table grants every masked role its privileges again. The role
		// is not one of them any more, and the role that stays is.
		masked.touchTables(t)
		assert.Empty(t, l.privileges(t, role), "after a table changed")
		assert.NotEmpty(t, l.privileges(t, stays), "the masked role that stays keeps its privileges")

		mustExec(t, db, fmt.Sprintf("DROP ROLE %q;", role))
	})
}

// TestAccSecurityLabelRevokeOnDestroy runs the removal of a masked role under Terraform, as a user
// that is not a superuser: the label leaves the configuration, and afterwards the role can be
// dropped.
func TestAccSecurityLabelRevokeOnDestroy(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("%s is not set", resource.EnvTfAcc)
	}
	server := newTestServer(t)
	db := server.open(t)
	l := newMaskingLayout(t, server, db)

	const role = "pgrole_test_acc_leaver"
	masked := l.newMaskedDatabase(t, role)
	provider := fmt.Sprintf(`
provider "pgrole" {
  host     = %q
  port     = %d
  database = "postgres"
  username = %q
  password = "provisioner"
}
`, server.host, server.port, testProvisioner)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					createRole(t, db, role)
					t.Cleanup(func() { l.dropOwned(t, role, masked.name) })
				},
				Config: provider + fmt.Sprintf(`
resource "pgrole_security_label" "test" {
  role              = %q
  label             = "MASKED"
  revoke_on_destroy = true
}
`, role),
				Check: func(*terraform.State) error {
					masked.touchTables(t)
					if l.privileges(t, role) == "" {
						return errors.New("dynamic masking did not grant the role its privileges")
					}
					return nil
				},
			},
			{
				Config: provider,
				Check: func(*terraform.State) error {
					if held := l.privileges(t, role); held != "" {
						return fmt.Errorf("the role still holds privileges: %s", held)
					}
					_, err := db.Exec(fmt.Sprintf("DROP ROLE %q;", role))
					return err
				},
			},
		},
	})
}

// A resource written before revoke_on_destroy existed holds no value for it. Reading and deleting
// it must work as before.
func TestSecurityLabelResource_StateWithoutRevokeOnDestroy(t *testing.T) {
	t.Parallel()

	old := securityLabelModel{Role: testRole, Label: "MASKED"}
	require.True(t, old.RevokeOnDestroy.IsNull())

	r, mock := newMockedResource(t, NewSecurityLabelResource)
	expectRoleCheck(mock, true)
	mock.ExpectQuery("FROM pg_seclabels").WithArgs(testRole).
		WillReturnRows(sqlmock.NewRows([]string{"label"}).AddRow("MASKED"))
	mock.ExpectClose()

	resp := runRead(t, r, old)
	requireNoErrors(t, resp.Diagnostics)
	assertState(t, old, resp.State)

	var revoke types.Bool
	requireNoErrors(t, resp.State.GetAttribute(t.Context(), path.Root("revoke_on_destroy"), &revoke))
	assert.True(t, revoke.IsNull(), "Read must not give the attribute a value")
}
