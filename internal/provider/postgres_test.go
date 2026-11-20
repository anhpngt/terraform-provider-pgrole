package provider

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// The tests that use these helpers need a real PostgreSQL server, reached with the standard
// connection parameters of the provider. They are skipped unless PGROLE_TEST_HOST is set:
//
//	PGROLE_TEST_HOST=127.0.0.1 PGROLE_TEST_PORT=5432 go test ./...
//
// PGROLE_TEST_USERNAME and PGROLE_TEST_PASSWORD default to "postgres" and must be a superuser.
// The security label cases also need the anon extension to be loaded and are skipped without it.

type testServer struct {
	host, port, username, password string
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
	return testServer{
		host:     host,
		port:     env("PGROLE_TEST_PORT", "5432"),
		username: env("PGROLE_TEST_USERNAME", "postgres"),
		password: env("PGROLE_TEST_PASSWORD", "postgres"),
	}
}

// getter connects the way the provider does, as the given user.
func (s testServer) getter(username, password string) F {
	return GetStandardPostgresGetter(
		fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable", username, password, s.host, s.port),
	)
}

func (s testServer) providerConfig() string {
	return fmt.Sprintf(`
provider "pgrole" {
  host     = %q
  port     = %s
  database = "postgres"
  username = %q
  password = %q
}
`, s.host, s.port, s.username, s.password)
}

// open connects as the superuser, until the test ends.
func (s testServer) open(t *testing.T) *sql.DB {
	t.Helper()

	db, err := s.getter(s.username, s.password)(context.Background())
	if err != nil {
		t.Fatalf("connect as %s: %s", s.username, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustExec(t *testing.T, db *sql.DB, sqlstr string) {
	t.Helper()

	if _, err := db.Exec(sqlstr); err != nil {
		t.Fatalf("%s: %s", sqlstr, err)
	}
}

// createRole creates a role that is dropped again when the test ends.
func createRole(t *testing.T, db *sql.DB, role string) {
	t.Helper()

	mustExec(t, db, fmt.Sprintf("DROP ROLE IF EXISTS %q;", role))
	mustExec(t, db, fmt.Sprintf("CREATE ROLE %q;", role))
	t.Cleanup(func() { dropRole(t, db, role) })
}

func dropRole(t *testing.T, db *sql.DB, role string) {
	t.Helper()

	mustExec(t, db, fmt.Sprintf("DROP ROLE IF EXISTS %q;", role))
}

// hasAnon reports whether the server accepts security labels of the anon provider.
func hasAnon(t *testing.T, db *sql.DB) bool {
	t.Helper()

	const role = "pgrole_test_anon_probe"
	createRole(t, db, role)
	_, err := db.Exec(sqlRemoveSecurityLabel(role))
	return err == nil
}

// A roleSettingCase describes one resource type by the setting it manages.
type roleSettingCase struct {
	name     string
	resource func() fwresource.Resource
	// set gives the role the setting, as Create does.
	set func(role string) string
	// managed is the state of the resource once the setting is in place.
	managed func(role string) any
	// unset is what Read reports for a role that does not have the setting.
	unset     func(role string) any
	needsAnon bool
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

// configured returns the resource of a case, connected as the given user.
func (c roleSettingCase) configured(t *testing.T, getDB F) fwresource.Resource {
	t.Helper()

	return configured(t, c.resource(), getDB)
}

// configured connects a resource as the given user.
func configured(t *testing.T, r fwresource.Resource, getDB F) fwresource.Resource {
	t.Helper()

	configurable, ok := r.(fwresource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("%T cannot be configured", r)
	}
	var resp fwresource.ConfigureResponse
	configurable.Configure(context.Background(), fwresource.ConfigureRequest{ProviderData: getDB}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("configure: %v", resp.Diagnostics)
	}
	return r
}

// stateOf returns the Terraform state holding the given model of a resource.
func stateOf(t *testing.T, r fwresource.Resource, model any) tfsdk.State {
	t.Helper()

	var schemaResp fwresource.SchemaResponse
	r.Schema(context.Background(), fwresource.SchemaRequest{}, &schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(context.Background(), model); diags.HasError() {
		t.Fatalf("build state: %v", diags)
	}
	return state
}

// read runs Read on a state and returns the refreshed model, or nil when Read removed the resource.
func read(t *testing.T, r fwresource.Resource, model any) any {
	t.Helper()

	state := stateOf(t, r, model)
	resp := fwresource.ReadResponse{State: state}
	r.Read(context.Background(), fwresource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		return nil
	}

	got := reflect.New(reflect.TypeOf(model))
	if diags := resp.State.Get(context.Background(), got.Interface()); diags.HasError() {
		t.Fatalf("decode state: %v", diags)
	}
	return got.Elem().Interface()
}

// createResource runs Create with the given model as the plan and returns the error it reports, if any.
func createResource(r fwresource.Resource, model any) string {
	ctx := context.Background()

	var schemaResp fwresource.SchemaResponse
	r.Schema(ctx, fwresource.SchemaRequest{}, &schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(ctx, model); diags.HasError() {
		return fmt.Sprintf("build plan: %v", diags)
	}
	resp := fwresource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, fwresource.CreateRequest{Plan: plan}, &resp)

	var msgs []string
	for _, d := range resp.Diagnostics.Errors() {
		msgs = append(msgs, d.Summary()+": "+d.Detail())
	}
	return strings.Join(msgs, "; ")
}

// deleteResource runs Delete on a state and returns the error it reports, if any.
func deleteResource(t *testing.T, r fwresource.Resource, model any) string {
	t.Helper()

	state := stateOf(t, r, model)
	resp := fwresource.DeleteResponse{State: state}
	r.Delete(context.Background(), fwresource.DeleteRequest{State: state}, &resp)

	var msgs []string
	for _, d := range resp.Diagnostics.Errors() {
		msgs = append(msgs, d.Summary()+": "+d.Detail())
	}
	return strings.Join(msgs, "; ")
}
