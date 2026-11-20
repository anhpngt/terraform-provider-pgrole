package provider

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/require"
)

// The tests that use these helpers need a real PostgreSQL server, reached with
// the standard connection parameters of the provider. They are skipped unless
// PGROLE_TEST_HOST is set:
//
//	PGROLE_TEST_HOST=127.0.0.1 PGROLE_TEST_PORT=5432 go test ./...
//
// PGROLE_TEST_USERNAME and PGROLE_TEST_PASSWORD default to "postgres" and must
// be a superuser. The security label cases also need the anon extension to be
// loaded, and are skipped without it.

type testServer struct {
	host               string
	port               int64
	username, password string
}

func newTestServer(t *testing.T) testServer {
	t.Helper()

	host := os.Getenv("PGROLE_TEST_HOST")
	if host == "" {
		t.Skip("PGROLE_TEST_HOST is not set")
	}

	env := func(name, fallback string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return fallback
	}
	port, err := strconv.ParseInt(env("PGROLE_TEST_PORT", "5432"), 10, 64)
	require.NoError(t, err, "PGROLE_TEST_PORT")

	return testServer{
		host:     host,
		port:     port,
		username: env("PGROLE_TEST_USERNAME", "postgres"),
		password: env("PGROLE_TEST_PASSWORD", "postgres"),
	}
}

// getter connects the way the provider does, as the given user.
func (s testServer) getter(username, password string) F {
	return GetStandardPostgresGetter(standardPostgresDSN(standardPostgresConfig{
		Username: username,
		Password: password,
		Host:     s.host,
		Port:     s.port,
		Database: "postgres",
		SSLMode:  "disable",
	}))
}

func (s testServer) providerConfig() string {
	return fmt.Sprintf(`
provider "pgrole" {
  host     = %q
  port     = %d
  database = "postgres"
  username = %q
  password = %q
}
`, s.host, s.port, s.username, s.password)
}

// open connects as the superuser, until the test ends.
func (s testServer) open(t *testing.T) *sql.DB {
	t.Helper()

	db, err := s.getter(s.username, s.password)(t.Context())
	require.NoError(t, err, "connect as %s", s.username)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// mustExec runs a statement and fails the test if the statement fails. It does
// not use t.Context(), because cleanup functions call it after that context is
// canceled.
func mustExec(t *testing.T, db *sql.DB, sqlstr string) {
	t.Helper()

	_, err := db.Exec(sqlstr)
	require.NoError(t, err, sqlstr)
}

// createRole creates a role that is dropped again when the test ends.
func createRole(t *testing.T, db *sql.DB, role string) {
	t.Helper()

	dropRole(t, db, role)
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q;", role))
	t.Cleanup(func() { dropRole(t, db, role) })
}

func dropRole(t *testing.T, db *sql.DB, role string) {
	t.Helper()

	mustExec(t, db, fmt.Sprintf("DROP ROLE IF EXISTS %q;", role))
}

// hasAnon reports whether the server accepts security labels of the anon
// provider.
func hasAnon(t *testing.T, db *sql.DB) bool {
	t.Helper()

	const role = "pgrole_test_anon_probe"
	createRole(t, db, role)
	_, err := db.Exec(sqlRemoveSecurityLabel(role))
	return err == nil
}

// readModel runs Read on the given model, and returns the refreshed model, or
// nil when Read removed the resource from the state.
func readModel(t *testing.T, r resource.Resource, model any) any {
	t.Helper()

	resp := runRead(t, r, model)
	requireNoErrors(t, resp.Diagnostics)
	if resp.State.Raw.IsNull() {
		return nil
	}
	return decodeState(t, resp.State, model)
}

// A roleSettingCase describes one resource type by the setting it manages.
type roleSettingCase struct {
	name     string
	resource func() resource.Resource
	// set gives the role the setting, as Create does.
	set func(role string) string
	// managed is the state of the resource once the setting is in place.
	managed func(role string) any
	// unset is what Read reports for a role that does not have the setting.
	unset     func(role string) any
	needsAnon bool
}

// configured returns the resource of the case, connected with the getter.
func (c roleSettingCase) configured(t *testing.T, getDB F) resource.Resource {
	t.Helper()

	return configured(t, c.resource(), getDB)
}

var roleSettingCases = []roleSettingCase{
	{
		name:     "audit",
		resource: NewAuditResource,
		set:      func(role string) string { return sqlSetAuditLog(role, "all") },
		managed:  func(role string) any { return auditModel{Role: role, AuditLogOption: "all"} },
		unset:    func(role string) any { return auditModel{Role: role, AuditLogOption: "none"} },
	},
	{
		name:     "statement_timeout",
		resource: NewStatementTimeoutResource,
		set:      func(role string) string { return sqlSetStatementTimeout(role, "300s") },
		managed:  func(role string) any { return statementTimeoutModel{Role: role, Timeout: "300s"} },
		unset:    func(role string) any { return statementTimeoutModel{Role: role, Timeout: "0s"} },
	},
	{
		name:      "security_label",
		resource:  NewSecurityLabelResource,
		set:       func(role string) string { return sqlSetSecurityLabel(role, "MASKED") },
		managed:   func(role string) any { return securityLabelModel{Role: role, Label: "MASKED"} },
		unset:     func(role string) any { return securityLabelModel{Role: role, Label: ""} },
		needsAnon: true,
	},
	{
		name:     "bypassrls",
		resource: NewBypassRLSResource,
		set:      sqlEnableBypassRLS,
		managed:  func(role string) any { return bypassrlsModel{Role: role, Enabled: true} },
		unset:    func(role string) any { return bypassrlsModel{Role: role, Enabled: false} },
	},
	{
		name:     "connection_limit",
		resource: NewConnectionLimitResource,
		set:      func(role string) string { return sqlSetConnectionLimit(role, 5) },
		managed:  func(role string) any { return connectionLimitModel{Role: role, ConnectionLimit: 5} },
		unset:    func(role string) any { return connectionLimitModel{Role: role, ConnectionLimit: -1} },
	},
	{
		name:     "createrole",
		resource: NewCreateRoleResource,
		set:      sqlEnableCreateRole,
		managed:  func(role string) any { return createRoleModel{Role: role, Enabled: true} },
		unset:    func(role string) any { return createRoleModel{Role: role, Enabled: false} },
	},
	{
		name:     "replication",
		resource: NewReplicationResource,
		set:      sqlEnableReplication,
		managed:  func(role string) any { return replicationModel{Role: role, Enabled: true} },
		unset:    func(role string) any { return replicationModel{Role: role, Enabled: false} },
	},
}
