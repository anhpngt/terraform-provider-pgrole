package provider

import (
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestSecurityLabelSQL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"set", sqlSetSecurityLabel("app", "MASKED"), `SECURITY LABEL FOR anon ON ROLE "app" IS 'MASKED';`},
		{"escape quote", sqlSetSecurityLabel("app", "it's"), `SECURITY LABEL FOR anon ON ROLE "app" IS 'it''s';`},
		{"remove", sqlRemoveSecurityLabel("app"), `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`},
		{"double quote in role name", sqlRemoveSecurityLabel(`a"b`), `SECURITY LABEL FOR anon ON ROLE "a""b" IS NULL;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

func TestSecurityLabelResource_CRUD(t *testing.T) {
	t.Parallel()

	readSQL := exact(sqlReadSecurityLabel)

	model := func(label string) securityLabelModel {
		return securityLabelModel{Role: testRole, Label: label}
	}

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS 'MASKED';`)
		mock.ExpectClose()

		resp := runCreate(t, r, model("MASKED"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("MASKED"), resp.State)
	})

	readcases := []struct {
		name     string
		rows     *sqlmock.Rows
		expected string
	}{
		{"read label", sqlmock.NewRows([]string{"label"}).AddRow("CUSTOM"), "CUSTOM"},
		{"read null label", sqlmock.NewRows([]string{"label"}).AddRow(nil), ""},
		{"read no label", sqlmock.NewRows([]string{"label"}), ""},
	}
	for _, tc := range readcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, mock := newMockedResource(t, NewSecurityLabelResource)
			expectRoleCheck(mock, true)
			mock.ExpectQuery(readSQL).WithArgs(testRole).WillReturnRows(tc.rows)
			mock.ExpectClose()

			resp := runRead(t, r, model("MASKED"))
			requireNoErrors(t, resp.Diagnostics)
			assertState(t, model(tc.expected), resp.State)
		})
	}

	t.Run("read query error", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectRoleCheck(mock, true)
		mock.ExpectQuery(readSQL).WithArgs(testRole).WillReturnError(sql.ErrConnDone)
		mock.ExpectClose()

		assertError(t, runRead(t, r, model("MASKED")).Diagnostics, "Failed to query security label")
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS 'CUSTOM';`)
		mock.ExpectClose()

		resp := runUpdate(t, r, model("MASKED"), model("CUSTOM"))
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, model("CUSTOM"), resp.State)
	})

	t.Run("delete removes the label", func(t *testing.T) {
		t.Parallel()

		r, mock := newMockedResource(t, NewSecurityLabelResource)
		expectExec(mock, `SECURITY LABEL FOR anon ON ROLE "app" IS NULL;`)
		mock.ExpectClose()

		requireNoErrors(t, runDelete(t, r, model("MASKED")).Diagnostics)
	})

	t.Run("import", func(t *testing.T) {
		t.Parallel()

		// Import sets only the role. The label stays null until Read, so
		// the model struct, which has no null string, cannot hold it.
		for _, roleName := range []string{testRole, "jane.doe@example.com"} {
			resp := runImport(t, NewSecurityLabelResource(), roleName)
			requireNoErrors(t, resp.Diagnostics)

			var role, label types.String
			requireNoErrors(t, resp.State.GetAttribute(t.Context(), path.Root("role"), &role))
			requireNoErrors(t, resp.State.GetAttribute(t.Context(), path.Root("label"), &label))
			assert.Equal(t, roleName, role.ValueString())
			assert.True(t, label.IsNull(), "label must be null after import, got %s", label)
		}
	})

	t.Run("read uses raw rolname for email role", func(t *testing.T) {
		t.Parallel()

		const emailRole = "jane.doe@example.com"
		r, mock := newMockedResource(t, NewSecurityLabelResource)
		mock.ExpectQuery(exact(roleExistsSQL)).WithArgs(emailRole).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectQuery(readSQL).WithArgs(emailRole).
			WillReturnRows(sqlmock.NewRows([]string{"label"}).AddRow("MASKED"))
		mock.ExpectClose()

		state := securityLabelModel{Role: emailRole, Label: "MASKED"}
		resp := runRead(t, r, state)
		requireNoErrors(t, resp.Diagnostics)
		assertState(t, state, resp.State)
		assert.Contains(t, sqlReadSecurityLabel, "pg_shseclabel")
		assert.Contains(t, sqlReadSecurityLabel, "rolname = $1")
	})
}

func TestSecurityLabelResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + `
resource "pgrole_security_label" "test" {
  role  = "test_role"
  label = "MASKED"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_security_label.test", "role", "test_role"),
					resource.TestCheckResourceAttr("pgrole_security_label.test", "label", "MASKED"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "pgrole_security_label.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "pgrole_security_label" "test" {
  role  = "test_role"
  label = "CUSTOM_LABEL"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_security_label.test", "role", "test_role"),
					resource.TestCheckResourceAttr("pgrole_security_label.test", "label", "CUSTOM_LABEL"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
