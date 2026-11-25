package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestCreateRoleSQL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"enable", sqlEnableCreateRole("app"), `ALTER ROLE "app" CREATEROLE;`},
		{"disable", sqlDisableCreateRole("app"), `ALTER ROLE "app" NOCREATEROLE;`},
		{"double quote in role name", sqlEnableCreateRole(`a"b`), `ALTER ROLE "a""b" CREATEROLE;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

func TestCreateRoleResource_CRUD(t *testing.T) {
	t.Parallel()

	testFlagResource(t, flagResourceSpec{
		newResource:  NewCreateRoleResource,
		model:        func(enabled bool) any { return createRoleModel{Role: testRole, Enabled: enabled} },
		enableSQL:    `ALTER ROLE "app" CREATEROLE;`,
		disableSQL:   `ALTER ROLE "app" NOCREATEROLE;`,
		readSQL:      "SELECT rolcreaterole FROM pg_roles WHERE rolname = $1;",
		column:       "rolcreaterole",
		queryFailure: "Failed to query CREATEROLE status",
	})
}

func TestCreateRoleResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + `
resource "pgrole_createrole" "test" {
  role    = "test"
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_createrole.test", "role", "test"),
					resource.TestCheckResourceAttr("pgrole_createrole.test", "enabled", "true"),
				),
			},
		},
	})
}
