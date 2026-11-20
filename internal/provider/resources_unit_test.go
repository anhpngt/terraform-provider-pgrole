package provider

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The helpers below call the resource methods the same way that the
// framework does, with the request and the initial response state that the
// framework sets.

func doCreate(r resource.Resource, s schema.Schema, plan map[string]tftypes.Value) *resource.CreateResponse {
	resp := &resource.CreateResponse{State: emptyState(s)}
	r.Create(context.Background(), resource.CreateRequest{Plan: newPlan(s, plan)}, resp)
	return resp
}

func doRead(r resource.Resource, s schema.Schema, state map[string]tftypes.Value) *resource.ReadResponse {
	resp := &resource.ReadResponse{State: newState(s, state)}
	r.Read(context.Background(), resource.ReadRequest{State: newState(s, state)}, resp)
	return resp
}

func doUpdate(r resource.Resource, s schema.Schema, prior, plan map[string]tftypes.Value) *resource.UpdateResponse {
	resp := &resource.UpdateResponse{State: newState(s, prior)}
	r.Update(context.Background(), resource.UpdateRequest{Plan: newPlan(s, plan), State: newState(s, prior)}, resp)
	return resp
}

func doDelete(r resource.Resource, s schema.Schema, state map[string]tftypes.Value) *resource.DeleteResponse {
	resp := &resource.DeleteResponse{State: newState(s, state)}
	r.Delete(context.Background(), resource.DeleteRequest{State: newState(s, state)}, resp)
	return resp
}

func doImport(t *testing.T, r resource.Resource, s schema.Schema, id string) *resource.ImportStateResponse {
	t.Helper()

	ri, ok := r.(resource.ResourceWithImportState)
	require.True(t, ok, "%T does not implement resource.ResourceWithImportState", r)

	resp := &resource.ImportStateResponse{State: emptyState(s)}
	ri.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, resp)
	return resp
}

func expectExec(mock sqlmock.Sqlmock, sqlstr string) {
	mock.ExpectExec(exact(sqlstr)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectClose()
}

func expectExecError(mock sqlmock.Sqlmock, sqlstr string) {
	mock.ExpectExec(exact(sqlstr)).WillReturnError(errors.New(`role "app" does not exist`))
	mock.ExpectClose()
}

const roleExistsSQL = "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1);"

// expectRoleCheck expects the check that Read runs first, and that Delete runs
// after a failed statement.
func expectRoleCheck(mock sqlmock.Sqlmock, exists bool) {
	mock.ExpectQuery(exact(roleExistsSQL)).WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exists))
}

func expectRoleCheckError(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(exact(roleExistsSQL)).WithArgs("app").WillReturnError(sql.ErrConnDone)
}

// allResources lists every resource with the attributes for a valid state and
// the statement that Delete runs, so that the common tests can run for each
// resource.
var allResources = []struct {
	typeName    string
	newResource func() resource.Resource
	state       map[string]tftypes.Value
	deleteSQL   string
}{
	{"pgrole_audit", NewAuditResource, map[string]tftypes.Value{"role": str("app"), "audit_log_option": str("all")}, `ALTER ROLE "app" RESET pgaudit.log;`},
	{"pgrole_bypassrls", NewBypassRLSResource, map[string]tftypes.Value{"role": str("app"), "enabled": boolean(true)}, `ALTER ROLE "app" NOBYPASSRLS;`},
	{"pgrole_connection_limit", NewConnectionLimitResource, map[string]tftypes.Value{"role": str("app"), "connection_limit": num(10)}, `ALTER ROLE "app" CONNECTION LIMIT -1;`},
	{"pgrole_createrole", NewCreateRoleResource, map[string]tftypes.Value{"role": str("app"), "enabled": boolean(true)}, `ALTER ROLE "app" NOCREATEROLE;`},
	{"pgrole_replication", NewReplicationResource, map[string]tftypes.Value{"role": str("app"), "enabled": boolean(true)}, `ALTER ROLE "app" NOREPLICATION;`},
	{"pgrole_security_label", NewSecurityLabelResource, map[string]tftypes.Value{"role": str("app"), "label": str("MASKED")}, `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`},
	{"pgrole_statement_timeout", NewStatementTimeoutResource, map[string]tftypes.Value{"role": str("app"), "timeout": str("30s")}, `ALTER ROLE "app" RESET statement_timeout;`},
}

func TestResources_Read_RoleGone(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)

			// A dropped role takes its settings with it. Read removes the
			// resource from the state and runs no other query.
			expectRoleCheck(mock, false)
			mock.ExpectClose()

			resp := doRead(r, s, tc.state)
			requireNoDiags(t, resp.Diagnostics)
			assert.True(t, resp.State.Raw.IsNull(), "Read must remove the resource when the role is gone")
		})
	}
}

func TestResources_Read_RoleCheckError(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)
			expectRoleCheckError(mock)
			mock.ExpectClose()

			// A failed check must not remove the resource. Only a role that
			// is known to be gone does.
			resp := doRead(r, s, tc.state)
			requireErrorDiag(t, resp.Diagnostics, "Failed to check role")
			requireState(t, resp.State, objectValue(s, tc.state))
		})
	}
}

func TestResources_Delete_RoleGone(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)

			// The role was dropped after the plan. The statement fails, but
			// the setting is gone with the role, so Delete succeeds.
			mock.ExpectExec(exact(tc.deleteSQL)).WillReturnError(errors.New(`role "app" does not exist`))
			expectRoleCheck(mock, false)
			mock.ExpectClose()

			requireNoDiags(t, doDelete(r, s, tc.state).Diagnostics)
		})
	}
}

func TestResources_Delete_SQLError(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		for _, check := range []struct {
			name   string
			expect func(sqlmock.Sqlmock)
		}{
			{"role exists", func(m sqlmock.Sqlmock) { expectRoleCheck(m, true) }},
			{"role check fails", expectRoleCheckError},
		} {
			t.Run(tc.typeName+"/"+check.name, func(t *testing.T) {
				t.Parallel()

				r := tc.newResource()
				s := resourceSchema(t, r)
				getDB, mock := mockDB(t)
				configureResource(t, r, getDB)

				// When the role exists, or when the check cannot tell,
				// Delete reports the error of the statement.
				mock.ExpectExec(exact(tc.deleteSQL)).WillReturnError(errors.New("permission denied"))
				check.expect(mock)
				mock.ExpectClose()

				resp := doDelete(r, s, tc.state)
				requireErrorDiag(t, resp.Diagnostics, "Failed to execute SQL")
				assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "permission denied")
			})
		}
	}
}

func TestResources_Metadata(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			resp := &resource.MetadataResponse{}
			tc.newResource().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "pgrole"}, resp)
			assert.Equal(t, tc.typeName, resp.TypeName)

			resourceSchema(t, tc.newResource())
		})
	}
}

func TestResources_Configure(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			rc := tc.newResource().(resource.ResourceWithConfigure)

			// Terraform calls Configure before the provider is configured,
			// with no provider data. That must not be an error.
			resp := &resource.ConfigureResponse{}
			rc.Configure(context.Background(), resource.ConfigureRequest{}, resp)
			requireNoDiags(t, resp.Diagnostics)

			resp = &resource.ConfigureResponse{}
			rc.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not a getter"}, resp)
			assert.True(t, resp.Diagnostics.HasError(), "expected an error for the wrong provider data type")
		})
	}
}

func TestResources_ConnectionFailure(t *testing.T) {
	t.Parallel()

	const summary = "Failed to get database connection"

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			configureResource(t, r, failingDB())

			createResp := doCreate(r, s, tc.state)
			requireErrorDiag(t, createResp.Diagnostics, summary)
			assert.True(t, createResp.State.Raw.IsNull(), "Create must not save state when it fails")

			requireErrorDiag(t, doRead(r, s, tc.state).Diagnostics, summary)
			requireErrorDiag(t, doUpdate(r, s, tc.state, tc.state).Diagnostics, summary)
			requireErrorDiag(t, doDelete(r, s, tc.state).Diagnostics, summary)
		})
	}
}

// flagResources are the resources that turn one role attribute on or off.
var flagResources = []struct {
	typeName     string
	newResource  func() resource.Resource
	enableSQL    string
	disableSQL   string
	readSQL      string
	column       string
	queryFailure string
}{
	{
		typeName:     "pgrole_bypassrls",
		newResource:  NewBypassRLSResource,
		enableSQL:    `ALTER ROLE "app" BYPASSRLS;`,
		disableSQL:   `ALTER ROLE "app" NOBYPASSRLS;`,
		readSQL:      "SELECT rolbypassrls FROM pg_roles WHERE rolname = $1;",
		column:       "rolbypassrls",
		queryFailure: "Failed to query BYPASSRLS status",
	},
	{
		typeName:     "pgrole_createrole",
		newResource:  NewCreateRoleResource,
		enableSQL:    `ALTER ROLE "app" CREATEROLE;`,
		disableSQL:   `ALTER ROLE "app" NOCREATEROLE;`,
		readSQL:      "SELECT rolcreaterole FROM pg_roles WHERE rolname = $1;",
		column:       "rolcreaterole",
		queryFailure: "Failed to query CREATEROLE status",
	},
	{
		typeName:     "pgrole_replication",
		newResource:  NewReplicationResource,
		enableSQL:    `ALTER ROLE "app" REPLICATION;`,
		disableSQL:   `ALTER ROLE "app" NOREPLICATION;`,
		readSQL:      "SELECT rolreplication FROM pg_roles WHERE rolname = $1;",
		column:       "rolreplication",
		queryFailure: "Failed to query REPLICATION status",
	},
}

func flagState(enabled bool) map[string]tftypes.Value {
	return map[string]tftypes.Value{"role": str("app"), "enabled": boolean(enabled)}
}

func TestFlagResources_Create(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		for _, enabled := range []bool{true, false} {
			t.Run(tc.typeName, func(t *testing.T) {
				t.Parallel()

				r := tc.newResource()
				s := resourceSchema(t, r)
				getDB, mock := mockDB(t)
				configureResource(t, r, getDB)

				if enabled {
					expectExec(mock, tc.enableSQL)
				} else {
					expectExec(mock, tc.disableSQL)
				}

				resp := doCreate(r, s, flagState(enabled))
				requireNoDiags(t, resp.Diagnostics)
				requireState(t, resp.State, objectValue(s, flagState(enabled)))
			})
		}
	}
}

func TestFlagResources_Create_SQLError(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)
			expectExecError(mock, tc.enableSQL)

			resp := doCreate(r, s, flagState(true))
			requireErrorDiag(t, resp.Diagnostics, "Failed to execute SQL")
			assert.True(t, resp.State.Raw.IsNull(), "Create must not save state when the SQL fails")
		})
	}
}

func TestFlagResources_Read(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		// The value in the database wins over the value in the state, so
		// that Terraform detects a change made outside of Terraform.
		for _, actual := range []bool{true, false} {
			t.Run(tc.typeName, func(t *testing.T) {
				t.Parallel()

				r := tc.newResource()
				s := resourceSchema(t, r)
				getDB, mock := mockDB(t)
				configureResource(t, r, getDB)

				expectRoleCheck(mock, true)
				mock.ExpectQuery(exact(tc.readSQL)).WithArgs("app").
					WillReturnRows(sqlmock.NewRows([]string{tc.column}).AddRow(actual))
				mock.ExpectClose()

				resp := doRead(r, s, flagState(!actual))
				requireNoDiags(t, resp.Diagnostics)
				requireState(t, resp.State, objectValue(s, flagState(actual)))
			})
		}
	}
}

func TestFlagResources_Read_RoleDroppedAfterCheck(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)

			// The role exists at the check, and is dropped before the next
			// query. Read fails, and the next refresh removes the resource.
			expectRoleCheck(mock, true)
			mock.ExpectQuery(exact(tc.readSQL)).WithArgs("app").
				WillReturnRows(sqlmock.NewRows([]string{tc.column}))
			mock.ExpectClose()

			resp := doRead(r, s, flagState(true))
			requireErrorDiag(t, resp.Diagnostics, tc.queryFailure)
		})
	}
}

func TestFlagResources_Update(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)
			expectExec(mock, tc.disableSQL)

			resp := doUpdate(r, s, flagState(true), flagState(false))
			requireNoDiags(t, resp.Diagnostics)
			requireState(t, resp.State, objectValue(s, flagState(false)))
		})
	}
}

func TestFlagResources_Update_SQLError(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)
			expectExecError(mock, tc.disableSQL)

			resp := doUpdate(r, s, flagState(true), flagState(false))
			requireErrorDiag(t, resp.Diagnostics, "Failed to execute SQL")
			requireState(t, resp.State, objectValue(s, flagState(true)))
		})
	}
}

func TestFlagResources_Delete(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)

			// Delete turns the attribute off. It does not drop the role.
			expectExec(mock, tc.disableSQL)

			requireNoDiags(t, doDelete(r, s, flagState(true)).Diagnostics)
		})
	}
}

func TestFlagResources_ImportState(t *testing.T) {
	t.Parallel()

	for _, tc := range flagResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			s := resourceSchema(t, r)

			// Import sets a placeholder value. The Read after the import
			// replaces it with the value in the database.
			resp := doImport(t, r, s, "app")
			requireNoDiags(t, resp.Diagnostics)
			requireState(t, resp.State, objectValue(s, flagState(false)))
		})
	}
}

func connLimitState(limit int64) map[string]tftypes.Value {
	return map[string]tftypes.Value{"role": str("app"), "connection_limit": num(limit)}
}

func TestConnectionLimitResource_CRUD(t *testing.T) {
	t.Parallel()

	const readSQL = "SELECT rolconnlimit FROM pg_roles WHERE rolname = $1;"

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT 10;`)

		resp := doCreate(r, s, connLimitState(10))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, connLimitState(10)))
	})

	t.Run("read", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(exact(readSQL)).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"rolconnlimit"}).AddRow(25))
		mock.ExpectClose()

		resp := doRead(r, s, connLimitState(10))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, connLimitState(25)))
	})

	t.Run("read role dropped after check", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(exact(readSQL)).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"rolconnlimit"}))
		mock.ExpectClose()

		requireErrorDiag(t, doRead(r, s, connLimitState(10)).Diagnostics, "Failed to query CONNECTION LIMIT value")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT 0;`)

		resp := doUpdate(r, s, connLimitState(10), connLimitState(0))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, connLimitState(0)))
	})

	t.Run("delete removes the limit", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" CONNECTION LIMIT -1;`)

		requireNoDiags(t, doDelete(r, s, connLimitState(10)).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		r := NewConnectionLimitResource()
		s := resourceSchema(t, r)

		resp := doImport(t, r, s, "app")
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, connLimitState(-1)))
	})
}

func timeoutState(timeout string) map[string]tftypes.Value {
	return map[string]tftypes.Value{"role": str("app"), "timeout": str(timeout)}
}

func TestStatementTimeoutResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := regexp.QuoteMeta("WHERE setting LIKE 'statement_timeout=%' LIMIT 1;")

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" SET statement_timeout = '30s';`)

		resp := doCreate(r, s, timeoutState("30s"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, timeoutState("30s")))
	})

	t.Run("read strips the setting name", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"setting"}).AddRow("statement_timeout=60s"))
		mock.ExpectClose()

		resp := doRead(r, s, timeoutState("30s"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, timeoutState("60s")))
	})

	t.Run("read with no setting", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"setting"}))
		mock.ExpectClose()

		resp := doRead(r, s, timeoutState("30s"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, timeoutState("0s")))
	})

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		requireErrorDiag(t, doRead(r, s, timeoutState("30s")).Diagnostics, "Failed to execute SQL")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" SET statement_timeout = '90s';`)

		resp := doUpdate(r, s, timeoutState("30s"), timeoutState("90s"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, timeoutState("90s")))
	})

	t.Run("delete resets the setting", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" RESET statement_timeout;`)

		requireNoDiags(t, doDelete(r, s, timeoutState("30s")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		r := NewStatementTimeoutResource()
		s := resourceSchema(t, r)

		resp := doImport(t, r, s, "app")
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, timeoutState("0s")))
	})
}

func auditState(option string) map[string]tftypes.Value {
	return map[string]tftypes.Value{"role": str("app"), "audit_log_option": str(option)}
}

func TestAuditResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := regexp.QuoteMeta("WHERE setting LIKE 'pgaudit.log=%' LIMIT 1;")

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" SET pgaudit.log = 'read, write';`)

		resp := doCreate(r, s, auditState("read, write"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, auditState("read, write")))
	})

	t.Run("read strips the setting name", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"setting"}).AddRow("pgaudit.log=ddl"))
		mock.ExpectClose()

		resp := doRead(r, s, auditState("all"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, auditState("ddl")))
	})

	t.Run("read with no setting", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").
			WillReturnRows(sqlmock.NewRows([]string{"setting"}))
		mock.ExpectClose()

		resp := doRead(r, s, auditState("all"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, auditState("none")))
	})

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		requireErrorDiag(t, doRead(r, s, auditState("all")).Diagnostics, "Failed to query pgaudit.log value")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" SET pgaudit.log = 'none';`)

		resp := doUpdate(r, s, auditState("all"), auditState("none"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, auditState("none")))
	})

	t.Run("delete resets the setting", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `ALTER ROLE "app" RESET pgaudit.log;`)

		requireNoDiags(t, doDelete(r, s, auditState("all")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		r := NewAuditResource()
		s := resourceSchema(t, r)

		resp := doImport(t, r, s, "app")
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, auditState("none")))
	})
}

func labelState(label string) map[string]tftypes.Value {
	return map[string]tftypes.Value{"role": str("app"), "label": str(label)}
}

func TestSecurityLabelResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := regexp.QuoteMeta("FROM pg_seclabels")

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r := NewSecurityLabelResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS 'MASKED';`)

		resp := doCreate(r, s, labelState("MASKED"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, labelState("MASKED")))
	})

	for _, tc := range []struct {
		name     string
		rows     *sqlmock.Rows
		expected string
	}{
		{"read label", sqlmock.NewRows([]string{"label"}).AddRow("CUSTOM"), "CUSTOM"},
		{"read null label", sqlmock.NewRows([]string{"label"}).AddRow(nil), ""},
		{"read no label", sqlmock.NewRows([]string{"label"}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := NewSecurityLabelResource()
			s := resourceSchema(t, r)
			getDB, mock := mockDB(t)
			configureResource(t, r, getDB)
			expectRoleCheck(mock, true)
			mock.ExpectQuery(readSQL).WithArgs("app").WillReturnRows(tc.rows)
			mock.ExpectClose()

			resp := doRead(r, s, labelState("MASKED"))
			requireNoDiags(t, resp.Diagnostics)
			requireState(t, resp.State, objectValue(s, labelState(tc.expected)))
		})
	}

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r := NewSecurityLabelResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs("app").WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		requireErrorDiag(t, doRead(r, s, labelState("MASKED")).Diagnostics, "Failed to query security label")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r := NewSecurityLabelResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS 'CUSTOM';`)

		resp := doUpdate(r, s, labelState("MASKED"), labelState("CUSTOM"))
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, labelState("CUSTOM")))
	})

	t.Run("delete removes the label", func(t *testing.T) {
		t.Parallel()

		r := NewSecurityLabelResource()
		s := resourceSchema(t, r)
		getDB, mock := mockDB(t)
		configureResource(t, r, getDB)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`)

		requireNoDiags(t, doDelete(r, s, labelState("MASKED")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		r := NewSecurityLabelResource()
		s := resourceSchema(t, r)

		// Import sets only the role. The label stays null until Read.
		resp := doImport(t, r, s, "app")
		requireNoDiags(t, resp.Diagnostics)
		requireState(t, resp.State, objectValue(s, map[string]tftypes.Value{
			"role":  str("app"),
			"label": tftypes.NewValue(tftypes.String, nil),
		}))
	})
}
