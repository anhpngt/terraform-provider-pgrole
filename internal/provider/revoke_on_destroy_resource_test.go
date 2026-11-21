package provider

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
)

var revokeModel = revokeOnDestroyModel{Role: testRole}

func warningText(diags diag.Diagnostics) string {
	var msgs []string
	for _, d := range diags.Warnings() {
		msgs = append(msgs, d.Summary()+": "+d.Detail())
	}
	return strings.Join(msgs, "; ")
}

func expectRoleOID(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(exact(sqlRoleOID)).WithArgs(testRole).
		WillReturnRows(sqlmock.NewRows([]string{"oid"}).AddRow(testRoleOID))
}

// expectDependencies makes the mock report what the role holds, as rows of
// database, kind and count.
func expectDependencies(mock sqlmock.Sqlmock, deps ...roleDependency) {
	rows := sqlmock.NewRows([]string{"datname", "deptype", "count"})
	for _, d := range deps {
		rows.AddRow(d.database, d.kind, d.count)
	}
	mock.ExpectQuery(exact(sqlRoleDependencies)).WithArgs(testRoleOID).WillReturnRows(rows)
}

// expectSecurityLabels makes the mock report the providers of the security
// labels of the role.
func expectSecurityLabels(mock sqlmock.Sqlmock, providers ...string) {
	rows := sqlmock.NewRows([]string{"provider"})
	for _, provider := range providers {
		rows.AddRow(provider)
	}
	mock.ExpectQuery(exact(sqlRoleSecurityLabelProviders)).WithArgs(testRoleOID).WillReturnRows(rows)
}

// expectOwners makes the mock report the owners of the objects that the role
// holds privileges on, as pairs of database and owner.
func expectOwners(mock sqlmock.Sqlmock, owners ...[2]string) {
	rows := sqlmock.NewRows([]string{"datname", "owner"})
	for _, o := range owners {
		rows.AddRow(o[0], o[1])
	}
	mock.ExpectQuery(exact(sqlPrivilegeObjectOwners)).WithArgs(testRoleOID).WillReturnRows(rows)
}

func expectHasPrivilegesOf(mock sqlmock.Sqlmock, role string, has bool) {
	mock.ExpectQuery(exact(sqlHasPrivilegesOfRole)).WithArgs(role).
		WillReturnRows(sqlmock.NewRows([]string{"pg_has_role"}).AddRow(has))
}

// expectCurrentDatabase makes the mock report testDatabase as the database of
// the provider configuration.
func expectCurrentDatabase(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(exact(sqlCurrentDatabase)).
		WillReturnRows(sqlmock.NewRows([]string{"current_database"}).AddRow(testDatabase))
}

func expectOwnedInCurrentDatabase(mock sqlmock.Sqlmock, owned int) {
	mock.ExpectQuery(exact(sqlOwnedInCurrentDatabase)).WithArgs(testRoleOID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(owned))
}

func TestRevokeOnDestroy_Schema(t *testing.T) {
	t.Parallel()

	r := NewRevokeOnDestroyResource()
	resp := &fwresource.MetadataResponse{}
	r.Metadata(t.Context(), fwresource.MetadataRequest{ProviderTypeName: "pgrole"}, resp)
	assert.Equal(t, "pgrole_revoke_on_destroy", resp.TypeName)

	// The resource is about one role for its whole life: another role means
	// another resource, so that the destroy runs for the first one.
	role, ok := resourceSchema(t, r).Attributes["role"].(schema.StringAttribute)
	require.True(t, ok)
	assert.True(t, role.Required)
	assert.Len(t, role.PlanModifiers, 1, "role must require a replacement")
}

func TestRevokeOnDestroy_Configure(t *testing.T) {
	t.Parallel()

	rc, ok := NewRevokeOnDestroyResource().(fwresource.ResourceWithConfigure)
	require.True(t, ok)

	resp := &fwresource.ConfigureResponse{}
	rc.Configure(t.Context(), fwresource.ConfigureRequest{}, resp)
	requireNoErrors(t, resp.Diagnostics)

	resp = &fwresource.ConfigureResponse{}
	rc.Configure(t.Context(), fwresource.ConfigureRequest{ProviderData: "not a getter"}, resp)
	assert.True(t, resp.Diagnostics.HasError(), "expected an error for the wrong provider data type")
}

func TestRevokeOnDestroy_Create(t *testing.T) {
	t.Parallel()

	t.Run("role exists", func(t *testing.T) {
		t.Parallel()

		// Create only checks the role. It changes nothing.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleCheck(mock, true)
		mock.ExpectClose()

		resp := runCreate(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, revokeModel, resp.State)
	})

	t.Run("role does not exist", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleCheck(mock, false)
		mock.ExpectClose()

		resp := runCreate(t, r, revokeModel)
		assertError(t, resp.Diagnostics, "Role does not exist")
		assertRemoved(t, resp.State)
	})

	t.Run("role check fails", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleCheckError(mock)
		mock.ExpectClose()

		resp := runCreate(t, r, revokeModel)
		assertError(t, resp.Diagnostics, "Failed to check role")
		assertRemoved(t, resp.State)
	})

	t.Run("connection failure", func(t *testing.T) {
		t.Parallel()

		resp := runCreate(t, configured(t, NewRevokeOnDestroyResource(), failingDB()), revokeModel)
		assertError(t, resp.Diagnostics, "Failed to get database connection")
		assertRemoved(t, resp.State)
	})
}

func TestRevokeOnDestroy_ReadAndUpdateNeedNoConnection(t *testing.T) {
	t.Parallel()

	// The resource holds nothing in the database, so a plan costs no
	// connection per role.
	r := configured(t, NewRevokeOnDestroyResource(), failingDB())

	readResp := runRead(t, r, revokeModel)
	requireNoErrors(t, readResp.Diagnostics)
	assertState(t, revokeModel, readResp.State)

	updateResp := runUpdate(t, r, revokeModel, revokeModel)
	requireNoErrors(t, updateResp.Diagnostics)
	assertState(t, revokeModel, updateResp.State)
}

func TestRevokeOnDestroy_Import(t *testing.T) {
	t.Parallel()

	resp := runImport(t, NewRevokeOnDestroyResource(), testRole)
	requireNoErrors(t, resp.Diagnostics)
	assertState(t, revokeModel, resp.State)
}

func TestRevokeOnDestroy_Delete(t *testing.T) {
	t.Parallel()

	privileges := roleDependency{database: testDatabase, kind: dependencyACL, count: 3}

	t.Run("connection failure", func(t *testing.T) {
		t.Parallel()

		resp := runDelete(t, configured(t, NewRevokeOnDestroyResource(), failingDB()), revokeModel)
		assertError(t, resp.Diagnostics, "Failed to get database connection")
	})

	t.Run("role is gone", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		mock.ExpectQuery(exact(sqlRoleOID)).WithArgs(testRole).WillReturnRows(sqlmock.NewRows([]string{"oid"}))
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("role holds nothing", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock)
		expectSecurityLabels(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("role owns objects in one database", func(t *testing.T) {
		t.Parallel()

		// DROP OWNED would drop the objects, so that database is left alone.
		// The label and the privileges elsewhere still go, and the destroy
		// succeeds with a warning.
		inApp := roleDependency{database: "app", kind: dependencyACL, count: 4}
		ownedInApp := roleDependency{database: "app", kind: "o", count: 2}

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, inApp, ownedInApp, privileges)
		expectSecurityLabels(mock, "anon")
		expectExec(mock, `SECURITY LABEL FOR "anon" ON ROLE "app" IS NULL;`)
		expectCurrentDatabase(mock)
		expectOwners(mock, [2]string{"app", "someone"})
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock, inApp, ownedInApp)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), `still has 4 privilege(s) in database "app", 2 owned object(s) in database "app"`)
		assert.Contains(t, warningText(resp.Diagnostics), `Database "app" was left alone`)
		assert.Contains(t, warningText(resp.Diagnostics), "REASSIGN OWNED BY")
	})

	t.Run("role owns objects and holds no privilege", func(t *testing.T) {
		t.Parallel()

		// Nothing to revoke. The warning says what the DROP ROLE will fail on.
		owned := roleDependency{database: "app", kind: "o", count: 2}

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, owned)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectDependencies(mock, owned)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), `still has 2 owned object(s) in database "app"`)
	})

	t.Run("role owns a database", func(t *testing.T) {
		t.Parallel()

		// DROP OWNED never drops a database, so the privileges still go.
		ownsDatabase := roleDependency{kind: "o", count: 1}

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, ownsDatabase, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock, ownsDatabase)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), "still has 1 owned object(s) on objects shared by all databases")
		assert.Contains(t, warningText(resp.Diagnostics), "It owns databases or tablespaces")
	})

	t.Run("privilege on a shared object only", func(t *testing.T) {
		t.Parallel()

		// It is revoked from the current database.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, roleDependency{kind: dependencyACL, count: 1})
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock, [2]string{"", "owner"})
		expectHasPrivilegesOf(mock, testRole, true)
		expectHasPrivilegesOf(mock, "owner", true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("label only", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock)
		expectSecurityLabels(mock, "anon")
		expectExec(mock, `SECURITY LABEL FOR "anon" ON ROLE "app" IS NULL;`)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("revokes with a membership taken for the time of the destroy", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		// The label goes before the privileges.
		expectSecurityLabels(mock, "anon")
		expectExec(mock, `SECURITY LABEL FOR "anon" ON ROLE "app" IS NULL;`)
		expectCurrentDatabase(mock)
		// An owner in a database that is not visited does not count.
		expectOwners(mock, [2]string{"other", "someone"}, [2]string{testDatabase, "owner"})
		// The user lacks the privileges of the role and gets them, and has
		// those of the owner already.
		expectHasPrivilegesOf(mock, testRole, false)
		expectExec(mock, `GRANT "app" TO CURRENT_USER;`)
		expectHasPrivilegesOf(mock, testRole, true)
		expectHasPrivilegesOf(mock, "owner", true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock)
		// Only the membership that the destroy gave is taken back.
		expectExec(mock, `REVOKE "app" FROM CURRENT_USER;`)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("membership cannot be taken", func(t *testing.T) {
		t.Parallel()

		// As on PostgreSQL 16 without ADMIN OPTION. The destroy succeeds with
		// a warning, and the DROP ROLE that follows reports the privileges.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock, [2]string{testDatabase, "owner"})
		expectHasPrivilegesOf(mock, testRole, false)
		expectExecError(mock, `GRANT "app" TO CURRENT_USER;`, errors.New(`permission denied to grant role "app"`))
		expectDependencies(mock, privileges)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), `3 privilege(s) in database "postgres"`)
		assert.Contains(t, warningText(resp.Diagnostics), `permission denied to grant role "app"`)
	})

	t.Run("membership without inherited privileges", func(t *testing.T) {
		t.Parallel()

		// A NOINHERIT user is a member after the GRANT and still cannot act
		// as the role. The membership is taken back.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, false)
		expectExec(mock, `GRANT "app" TO CURRENT_USER;`)
		expectHasPrivilegesOf(mock, testRole, false)
		expectDependencies(mock, privileges)
		expectExec(mock, `REVOKE "app" FROM CURRENT_USER;`)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), "does not inherit its privileges")
	})

	t.Run("a concurrent change is tried again", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExecError(mock, `DROP OWNED BY "app";`, &pq.Error{Code: "XX000", Message: "tuple concurrently updated"})
		mock.ExpectRollback()
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock)
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
	})

	t.Run("privileges are left", func(t *testing.T) {
		t.Parallel()

		// DROP OWNED only warns about a privilege it may not revoke. The
		// check afterwards finds it.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock, roleDependency{database: testDatabase, kind: dependencyACL, count: 1})
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), `still has 1 privilege(s) in database "postgres"`)
		assert.Contains(t, warningText(resp.Diagnostics), "PostgreSQL will refuse to drop it")
	})

	t.Run("role came to own an object", func(t *testing.T) {
		t.Parallel()

		// Between the first check and the DROP OWNED. Nothing is dropped.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 1)
		mock.ExpectRollback()
		expectDependencies(mock, privileges, roleDependency{database: testDatabase, kind: "o", count: 1})
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), "nothing was dropped")
	})

	t.Run("membership cannot be taken back", func(t *testing.T) {
		t.Parallel()

		// The one failure that leaves the provider's user with more than it
		// had. That is an error.
		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		expectDependencies(mock, privileges)
		expectSecurityLabels(mock)
		expectCurrentDatabase(mock)
		expectOwners(mock)
		expectHasPrivilegesOf(mock, testRole, false)
		expectExec(mock, `GRANT "app" TO CURRENT_USER;`)
		expectHasPrivilegesOf(mock, testRole, true)
		mock.ExpectBegin()
		expectOwnedInCurrentDatabase(mock, 0)
		expectExec(mock, `DROP OWNED BY "app";`)
		mock.ExpectCommit()
		expectDependencies(mock)
		expectExecError(mock, `REVOKE "app" FROM CURRENT_USER;`, errors.New("connection reset"))
		mock.ExpectClose()

		resp := runDelete(t, r, revokeModel)
		assertError(t, resp.Diagnostics, "Failed to revoke the privileges of the role")
		assert.Contains(t, diagError(resp.Diagnostics), `failed to take back the membership in role "app"`)
	})

	t.Run("catalog query fails", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewRevokeOnDestroyResource)
		expectRoleOID(mock)
		mock.ExpectQuery(exact(sqlRoleDependencies)).WithArgs(testRoleOID).WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		assertError(t, runDelete(t, r, revokeModel).Diagnostics, "Failed to revoke the privileges of the role")
	})
}

func TestQuoteIdentifier(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `"jane.doe@example.com"`, quoteIdentifier("jane.doe@example.com"))
	assert.Equal(t, `"a""b"`, quoteIdentifier(`a"b`))
	// A backslash is an ordinary character in an identifier.
	assert.Equal(t, `"a\b"`, quoteIdentifier(`a\b`))
}

func TestIsTransient(t *testing.T) {
	t.Parallel()

	assert.True(t, isTransient(&pq.Error{Code: "XX000", Message: "tuple concurrently updated"}))
	assert.True(t, isTransient(fmt.Errorf("wrapped: %w", &pq.Error{Code: "40P01", Message: "deadlock detected"})))
	assert.True(t, isTransient(&pq.Error{Code: "55P03", Message: "canceling statement due to lock timeout"}))
	assert.False(t, isTransient(&pq.Error{Code: "42501", Message: "permission denied"}))
	assert.False(t, isTransient(errors.New("tuple concurrently updated")), "only errors of the server count")
}

// The tests below need a PostgreSQL server. See helpers_postgres_test.go.
//
// Their roles and databases copy the layout that the resource is for:
// privileges that a role other than the provider's user granted, in more than
// one database.
const (
	testOwner       = "pgrole_test_owner"       // owns the objects and grants the privileges; not a superuser
	testProvisioner = "pgrole_test_provisioner" // the provider's user: CREATEROLE, not a member of the owner
	testNobody      = "pgrole_test_nobody"      // may log in and nothing else
)

var testDatabases = []string{"pgrole_test_db1", "pgrole_test_db2"}

// A privilegeLayout holds the connections of the test to the layout above.
type privilegeLayout struct {
	server    testServer
	superuser *sql.DB
	// owner is the connection of the owner to each test database.
	owner map[string]*sql.DB
	// adminOnly is true on PostgreSQL 16 and newer, where CREATEROLE alone no
	// longer lets a user grant itself any role. The provisioner then gets
	// ADMIN OPTION on a role, without its privileges, to be able to.
	adminOnly bool
}

func newPrivilegeLayout(t *testing.T, server testServer, db *sql.DB) privilegeLayout {
	t.Helper()

	var version int
	require.NoError(t, db.QueryRow("SELECT current_setting('server_version_num')::int;").Scan(&version))
	l := privilegeLayout{server: server, superuser: db, owner: map[string]*sql.DB{}, adminOnly: version >= 160000}

	drop := func() {
		for _, database := range testDatabases {
			mustExec(t, db, fmt.Sprintf("DROP DATABASE IF EXISTS %q;", database))
		}
		for _, role := range []string{testOwner, testProvisioner, testNobody} {
			dropRole(t, db, role)
		}
	}
	drop()
	// Registered before any connection to the test databases is opened, so
	// that it runs once they are closed: a database in use cannot be dropped.
	t.Cleanup(drop)

	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'owner';", testOwner))
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'provisioner' CREATEROLE;", testProvisioner))
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'nobody';", testNobody))
	l.letProvisionerAct(t, testOwner)

	for _, database := range testDatabases {
		mustExec(t, db, fmt.Sprintf("CREATE DATABASE %q OWNER %q TEMPLATE template0;", database, testOwner))
		conn := l.open(t, testOwner, "owner", database)
		mustExec(t, conn, "CREATE SCHEMA app;")
		mustExec(t, conn, "CREATE TABLE app.users (id int);")
		mustExec(t, conn, "CREATE VIEW app.users_view AS SELECT id FROM app.users;")
		mustExec(t, conn, "CREATE SEQUENCE app.users_seq;")
		l.owner[database] = conn
	}

	return l
}

// open connects to one of the test databases, until the test ends.
func (l privilegeLayout) open(t *testing.T, username, password, database string) *sql.DB {
	t.Helper()

	db, err := l.server.getter(username, password)(withDatabase(t.Context(), database))
	require.NoError(t, err, "connect to %s as %s", database, username)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// letProvisionerAct gives the provisioner what it needs to grant itself the
// role, where CREATEROLE is not enough.
func (l privilegeLayout) letProvisionerAct(t *testing.T, role string) {
	t.Helper()

	if l.adminOnly {
		mustExec(t, l.superuser, fmt.Sprintf("GRANT %q TO %q WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;", role, testProvisioner))
	}
}

// leaver creates a role that holds privileges on a schema and on the tables,
// views and sequences in it, in every test database, plus a privilege on a
// shared object. That is what dynamic masking gives a masked role.
func (l privilegeLayout) leaver(t *testing.T, role string) {
	t.Helper()

	createRole(t, l.superuser, role)
	l.letProvisionerAct(t, role)
	for _, conn := range l.owner {
		mustExec(t, conn, fmt.Sprintf("GRANT USAGE ON SCHEMA app TO %q;", role))
		mustExec(t, conn, fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA app TO %q;", role))
		mustExec(t, conn, fmt.Sprintf("GRANT SELECT ON ALL SEQUENCES IN SCHEMA app TO %q;", role))
	}
	mustExec(t, l.owner[testDatabases[0]], fmt.Sprintf("GRANT CONNECT ON DATABASE %q TO %q;", testDatabases[0], role))
}

// holds describes what makes PostgreSQL refuse to drop a role, "" when nothing
// does.
func (l privilegeLayout) holds(t *testing.T, role string) string {
	t.Helper()

	var oid int64
	require.NoError(t, l.superuser.QueryRow(sqlRoleOID, role).Scan(&oid), "look up %s", role)
	deps, err := roleDependencies(t.Context(), l.superuser, oid)
	require.NoError(t, err, "dependencies of %s", role)
	return describeDependencies(deps)
}

// provisionerMemberships lists the memberships of the provider's user, with
// who granted each.
func (l privilegeLayout) provisionerMemberships(t *testing.T) string {
	t.Helper()

	roles, err := queryStrings(t.Context(), l.superuser, `SELECT g.rolname || ' by ' || pg_get_userbyid(m.grantor)
FROM pg_auth_members m
JOIN pg_roles g ON g.oid = m.roleid
JOIN pg_roles r ON r.oid = m.member
WHERE r.rolname = $1
ORDER BY 1;`, testProvisioner)
	require.NoError(t, err, "memberships of %s", testProvisioner)
	return strings.Join(roles, ", ")
}

func (l privilegeLayout) resourceAs(t *testing.T, username, password string) fwresource.Resource {
	t.Helper()

	return configured(t, NewRevokeOnDestroyResource(), l.server.getter(username, password))
}

func TestRevokeOnDestroy(t *testing.T) {
	server := newTestServer(t)
	db := server.open(t)
	l := newPrivilegeLayout(t, server, db)

	provisioner := l.resourceAs(t, testProvisioner, "provisioner")
	model := func(role string) any { return revokeOnDestroyModel{Role: role} }

	t.Run("revokes what another role granted, in every database", func(t *testing.T) {
		const role = "pgrole_test_leaver"
		l.leaver(t, role)
		memberships := l.provisionerMemberships(t)

		_, err := db.Exec(fmt.Sprintf("DROP ROLE %q;", role))
		require.ErrorContains(t, err, "cannot be dropped because some objects depend on it", "before the destroy")

		resp := runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
		assert.Empty(t, l.holds(t, role))
		assert.Equal(t, memberships, l.provisionerMemberships(t), "the provider's user must keep no membership")

		mustExec(t, db, fmt.Sprintf("DROP ROLE %q;", role))
	})

	t.Run("leaves a database alone when the role owns objects there", func(t *testing.T) {
		const role = "pgrole_test_table_owner"
		l.leaver(t, role)
		memberships := l.provisionerMemberships(t)

		conn := l.open(t, server.username, server.password, testDatabases[1])
		mustExec(t, conn, "CREATE TABLE app.kept (id int);")
		mustExec(t, conn, fmt.Sprintf("ALTER TABLE app.kept OWNER TO %q;", role))
		// The table goes first, then the privileges, so that the role can be
		// dropped when the test ends. Deferred and not a cleanup function: the
		// context of the test is canceled before those run.
		defer func() {
			mustExec(t, conn, "DROP TABLE IF EXISTS app.kept;")
			requireNoErrors(t, runDelete(t, l.resourceAs(t, server.username, server.password), model(role)).Diagnostics)
		}()
		require.Contains(t, l.holds(t, role), `privilege(s) in database "pgrole_test_db1"`, "before the destroy")

		resp := runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), `Database "pgrole_test_db2" was left alone`)
		assert.Contains(t, warningText(resp.Diagnostics), "REASSIGN OWNED BY")
		// Only the database with the table is left as it was.
		assert.Equal(t, `4 privilege(s) in database "pgrole_test_db2", 1 owned object(s) in database "pgrole_test_db2"`, l.holds(t, role))
		assert.Equal(t, memberships, l.provisionerMemberships(t))

		var kept int
		require.NoError(t, conn.QueryRow("SELECT count(*) FROM pg_tables WHERE schemaname = 'app' AND tablename = 'kept';").Scan(&kept))
		assert.Equal(t, 1, kept, "the table of the role must still be there")
	})

	t.Run("does nothing for a role without privileges, or for a role that is gone", func(t *testing.T) {
		const role = "pgrole_test_plain"
		createRole(t, db, role)
		memberships := l.provisionerMemberships(t)

		resp := runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))

		dropRole(t, db, role)
		resp = runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
		assert.Equal(t, memberships, l.provisionerMemberships(t))
	})

	t.Run("warns when the user cannot act as the owner", func(t *testing.T) {
		const role = "pgrole_test_stuck"
		l.leaver(t, role)
		before := l.holds(t, role)

		// The destroy succeeds, so that Terraform goes on with the other
		// changes. The DROP ROLE that follows fails as it did before.
		resp := runDelete(t, l.resourceAs(t, testNobody, "nobody"), model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), "could not get")
		assert.Equal(t, before, l.holds(t, role))

		// A superuser needs no membership.
		resp = runDelete(t, l.resourceAs(t, server.username, server.password), model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
		assert.Empty(t, l.holds(t, role))
	})

	t.Run("CREATEROLE alone is not enough on PostgreSQL 16 and newer", func(t *testing.T) {
		if !l.adminOnly {
			t.Skip("before PostgreSQL 16, CREATEROLE lets a user grant itself any role")
		}
		const role = "pgrole_test_no_admin"
		l.leaver(t, role)
		mustExec(t, db, fmt.Sprintf("REVOKE %q FROM %q;", role, testProvisioner))
		before := l.holds(t, role)

		resp := runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Contains(t, warningText(resp.Diagnostics), "could not get")
		assert.Contains(t, warningText(resp.Diagnostics), "ADMIN OPTION")
		assert.Equal(t, before, l.holds(t, role))

		resp = runDelete(t, l.resourceAs(t, server.username, server.password), model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, l.holds(t, role))
	})

	t.Run("several roles at once", func(t *testing.T) {
		const count = 8
		roles := make([]string, count)
		for i := range roles {
			roles[i] = fmt.Sprintf("pgrole_test_leaver_%d", i)
			l.leaver(t, roles[i])
		}
		memberships := l.provisionerMemberships(t)

		// Build the requests here: the goroutines must not call the test
		// helpers.
		var wg sync.WaitGroup
		resps := make([]*fwresource.DeleteResponse, count)
		for i, role := range roles {
			req := fwresource.DeleteRequest{State: stateOf(t, provisioner, model(role))}
			resps[i] = &fwresource.DeleteResponse{State: stateOf(t, provisioner, model(role))}

			ctx := t.Context()
			wg.Go(func() { provisioner.Delete(ctx, req, resps[i]) })
		}
		wg.Wait()

		for i, role := range roles {
			assert.Empty(t, diagError(resps[i].Diagnostics), role)
			assert.Empty(t, warningText(resps[i].Diagnostics), role)
			assert.Empty(t, l.holds(t, role), role)
		}
		assert.Equal(t, memberships, l.provisionerMemberships(t), "the provider's user must keep no membership")
	})

	t.Run("dynamic masking does not grant the privileges again", func(t *testing.T) {
		if !hasAnon(t, db) {
			t.Skip("the anon extension is not loaded on the test server")
		}
		const role = "pgrole_test_masked"
		createRole(t, db, role)
		l.letProvisionerAct(t, role)
		mustExec(t, db, sqlSetSecurityLabel(role, "MASKED"))

		// The owner starts dynamic masking, which takes a superuser, and is an
		// ordinary role again afterwards. PostgreSQL Anonymizer then gives the
		// masked role its privileges in the name of the owner.
		mustExec(t, db, fmt.Sprintf("ALTER ROLE %q SUPERUSER;", testOwner))
		owner := l.open(t, testOwner, "owner", testDatabases[0])
		mustExec(t, owner, "CREATE EXTENSION anon CASCADE;")
		mustExec(t, owner, "SELECT anon.start_dynamic_masking();")
		mustExec(t, db, fmt.Sprintf("ALTER ROLE %q NOSUPERUSER;", testOwner))
		require.Contains(t, l.holds(t, role), `privilege(s) in database "pgrole_test_db1"`, "after dynamic masking started")

		resp := runDelete(t, provisioner, model(role))
		requireNoErrors(t, resp.Diagnostics)
		assert.Empty(t, warningText(resp.Diagnostics))
		assert.Empty(t, l.holds(t, role))

		var labels int
		require.NoError(t, db.QueryRow("SELECT count(*) FROM pg_shseclabel l JOIN pg_roles r ON r.oid = l.objoid WHERE r.rolname = $1;", role).Scan(&labels))
		assert.Zero(t, labels, "the security label of the role must be gone")

		// A new table makes PostgreSQL Anonymizer grant every masked role its
		// privileges again. The role is not one of them any more.
		mustExec(t, owner, "CREATE TABLE public.added_later (id int);")
		assert.Empty(t, l.holds(t, role), "after a table was created")
	})
}

// TestAccRevokeOnDestroy runs the removal of a role under Terraform, as a user
// that is not a superuser: the resource leaves the configuration, and
// afterwards the role can be dropped.
func TestAccRevokeOnDestroy(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("%s is not set", resource.EnvTfAcc)
	}
	server := newTestServer(t)
	db := server.open(t)
	l := newPrivilegeLayout(t, server, db)

	const role = "pgrole_test_acc_leaver"
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
				PreConfig: func() { l.leaver(t, role) },
				Config: provider + fmt.Sprintf(`
resource "pgrole_revoke_on_destroy" "test" {
  role = %q
}
`, role),
				Check: func(*terraform.State) error {
					if held := l.holds(t, role); !strings.Contains(held, "privilege(s)") {
						return fmt.Errorf("creating the resource changed what the role holds: %q", held)
					}
					return nil
				},
			},
			{
				Config: provider,
				Check: func(*terraform.State) error {
					if held := l.holds(t, role); held != "" {
						return fmt.Errorf("the role still has %s", held)
					}
					_, err := db.Exec(fmt.Sprintf("DROP ROLE %q;", role))
					return err
				},
			},
		},
	})
}
