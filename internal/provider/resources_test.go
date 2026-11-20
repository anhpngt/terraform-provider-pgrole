package provider

import (
	"errors"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allResources lists every resource with a valid state and the statement that
// Delete runs, so that the tests in this file run for each resource.
var allResources = []struct {
	typeName    string
	newResource func() resource.Resource
	model       any
	deleteSQL   string
}{
	{
		typeName:    "pgrole_audit",
		newResource: NewAuditResource,
		model:       auditModel{Role: testRole, AuditLogOption: "all"},
		deleteSQL:   `ALTER ROLE "app" RESET pgaudit.log;`,
	},
	{
		typeName:    "pgrole_bypassrls",
		newResource: NewBypassRLSResource,
		model:       bypassrlsModel{Role: testRole, Enabled: true},
		deleteSQL:   `ALTER ROLE "app" NOBYPASSRLS;`,
	},
	{
		typeName:    "pgrole_connection_limit",
		newResource: NewConnectionLimitResource,
		model:       connectionLimitModel{Role: testRole, ConnectionLimit: 10},
		deleteSQL:   `ALTER ROLE "app" CONNECTION LIMIT -1;`,
	},
	{
		typeName:    "pgrole_createrole",
		newResource: NewCreateRoleResource,
		model:       createRoleModel{Role: testRole, Enabled: true},
		deleteSQL:   `ALTER ROLE "app" NOCREATEROLE;`,
	},
	{
		typeName:    "pgrole_replication",
		newResource: NewReplicationResource,
		model:       replicationModel{Role: testRole, Enabled: true},
		deleteSQL:   `ALTER ROLE "app" NOREPLICATION;`,
	},
	{
		typeName:    "pgrole_security_label",
		newResource: NewSecurityLabelResource,
		model:       securityLabelModel{Role: testRole, Label: "MASKED"},
		deleteSQL:   `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`,
	},
	{
		typeName:    "pgrole_statement_timeout",
		newResource: NewStatementTimeoutResource,
		model:       statementTimeoutModel{Role: testRole, Timeout: "30s"},
		deleteSQL:   `ALTER ROLE "app" RESET statement_timeout;`,
	},
}

func TestResources_Metadata(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r := tc.newResource()
			resp := &resource.MetadataResponse{}
			r.Metadata(t.Context(), resource.MetadataRequest{ProviderTypeName: "pgrole"}, resp)

			assert.Equal(t, tc.typeName, resp.TypeName)
			resourceSchema(t, r)
		})
	}
}

func TestResources_Configure(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			rc, ok := tc.newResource().(resource.ResourceWithConfigure)
			require.True(t, ok)

			// Terraform calls Configure before the provider is configured,
			// with no provider data. That must not be an error.
			resp := &resource.ConfigureResponse{}
			rc.Configure(t.Context(), resource.ConfigureRequest{}, resp)
			requireNoErrors(t, resp.Diagnostics)

			resp = &resource.ConfigureResponse{}
			rc.Configure(t.Context(), resource.ConfigureRequest{ProviderData: "not a getter"}, resp)
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

			r := configured(t, tc.newResource(), failingDB())

			createResp := runCreate(t, r, tc.model)
			assertError(t, createResp.Diagnostics, summary)
			assertRemoved(t, createResp.State)

			assertError(t, runRead(t, r, tc.model).Diagnostics, summary)
			assertError(t, runUpdate(t, r, tc.model, tc.model).Diagnostics, summary)
			assertError(t, runDelete(t, r, tc.model).Diagnostics, summary)
		})
	}
}

func TestResources_Read_RoleGone(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, tc.newResource)

			// A dropped role takes its settings with it. Read removes the
			// resource from the state and runs no other query.
			expectRoleCheck(mock, false)
			mock.ExpectClose()

			resp := runRead(t, r, tc.model)
			requireNoErrors(t, resp.Diagnostics)
			assertRemoved(t, resp.State)
		})
	}
}

func TestResources_Read_RoleCheckError(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, tc.newResource)
			expectRoleCheckError(mock)
			mock.ExpectClose()

			// A failed check must not remove the resource. Only a role that
			// is known to be gone does.
			resp := runRead(t, r, tc.model)
			assertError(t, resp.Diagnostics, "Failed to check role")
			assertState(t, tc.model, resp.State)
		})
	}
}

func TestResources_Delete_RoleGone(t *testing.T) {
	t.Parallel()

	for _, tc := range allResources {
		t.Run(tc.typeName, func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, tc.newResource)

			// The role was dropped after the plan. The statement fails, but
			// the setting is gone with the role, so Delete succeeds.
			expectExecError(mock, tc.deleteSQL, errors.New(`role "app" does not exist`))
			expectRoleCheck(mock, false)
			mock.ExpectClose()

			requireNoErrors(t, runDelete(t, r, tc.model).Diagnostics)
		})
	}
}

func TestResources_Delete_SQLError(t *testing.T) {
	t.Parallel()

	checks := []struct {
		name   string
		expect func(sqlmock.Sqlmock)
	}{
		{"role exists", func(m sqlmock.Sqlmock) { expectRoleCheck(m, true) }},
		{"role check fails", expectRoleCheckError},
	}

	for _, tc := range allResources {
		for _, check := range checks {
			t.Run(tc.typeName+"/"+check.name, func(t *testing.T) {
				t.Parallel()

				r, mock := newMockedResource(t, tc.newResource)

				// When the role exists, or when the check cannot tell,
				// Delete reports the error of the statement.
				expectExecError(mock, tc.deleteSQL, errors.New("permission denied"))
				check.expect(mock)
				mock.ExpectClose()

				resp := runDelete(t, r, tc.model)
				assertError(t, resp.Diagnostics, "Failed to execute SQL")
				assert.Contains(t, diagError(resp.Diagnostics), "permission denied")
			})
		}
	}
}

// flagResourceSpec describes a resource that turns one role attribute on or
// off. testFlagResource runs the same tests for each of these resources.
type flagResourceSpec struct {
	newResource func() resource.Resource
	// model returns the state of the resource for role testRole.
	model        func(enabled bool) any
	enableSQL    string
	disableSQL   string
	readSQL      string
	column       string
	queryFailure string
}

func (s flagResourceSpec) sql(enabled bool) string {
	if enabled {
		return s.enableSQL
	}
	return s.disableSQL
}

func testFlagResource(t *testing.T, spec flagResourceSpec) {
	t.Helper()

	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("create enabled=%t", enabled), func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, spec.newResource)
			expectExec(mock, spec.sql(enabled))
			mock.ExpectClose()

			resp := runCreate(t, r, spec.model(enabled))
			requireNoErrors(t, resp.Diagnostics)
			assertState(t, spec.model(enabled), resp.State)
		})
	}

	t.Run("create SQL error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, spec.newResource)
		expectExecError(mock, spec.enableSQL, errors.New("permission denied"))
		mock.ExpectClose()

		resp := runCreate(t, r, spec.model(true))
		assertError(t, resp.Diagnostics, "Failed to execute SQL")
		assertRemoved(t, resp.State)
	})

	// The value in the database wins over the value in the state, so that
	// Terraform detects a change made outside of Terraform.
	for _, actual := range []bool{true, false} {
		t.Run(fmt.Sprintf("read enabled=%t", actual), func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, spec.newResource)
			expectRoleCheck(mock, true)
			mock.ExpectQuery(exact(spec.readSQL)).WithArgs(testRole).
				WillReturnRows(sqlmock.NewRows([]string{spec.column}).AddRow(actual))
			mock.ExpectClose()

			resp := runRead(t, r, spec.model(!actual))
			requireNoErrors(t, resp.Diagnostics)
			assertState(t, spec.model(actual), resp.State)
		})
	}

	t.Run("read role dropped after check", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, spec.newResource)

		// The role exists at the check, and is dropped before the next
		// query. Read fails, and the next refresh removes the resource.
		expectRoleCheck(mock, true)
		mock.ExpectQuery(exact(spec.readSQL)).WithArgs(testRole).
			WillReturnRows(sqlmock.NewRows([]string{spec.column}))
		mock.ExpectClose()

		assertError(t, runRead(t, r, spec.model(true)).Diagnostics, spec.queryFailure)
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, spec.newResource)
		expectExec(mock, spec.disableSQL)
		mock.ExpectClose()

		resp := runUpdate(t, r, spec.model(true), spec.model(false))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, spec.model(false), resp.State)
	})

	t.Run("update SQL error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, spec.newResource)
		expectExecError(mock, spec.disableSQL, errors.New("permission denied"))
		mock.ExpectClose()

		// A failed update keeps the prior state.
		resp := runUpdate(t, r, spec.model(true), spec.model(false))
		assertError(t, resp.Diagnostics, "Failed to execute SQL")
		assertState(t, spec.model(true), resp.State)
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, spec.newResource)

		// Delete turns the attribute off. It does not drop the role.
		expectExec(mock, spec.disableSQL)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, spec.model(true)).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		// Import sets a placeholder value. The Read after the import
		// replaces it with the value in the database.
		resp := runImport(t, spec.newResource(), testRole)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, spec.model(false), resp.State)
	})
}
