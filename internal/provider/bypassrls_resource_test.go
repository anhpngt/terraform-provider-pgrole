package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func TestBypassRLSSQL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		got      string
		expected string
	}{
		{"enable", sqlEnableBypassRLS("app"), `ALTER ROLE "app" BYPASSRLS;`},
		{"disable", sqlDisableBypassRLS("app"), `ALTER ROLE "app" NOBYPASSRLS;`},
		// Role names with upper case, dashes, and dots need quotes in SQL.
		{"quoted role name", sqlEnableBypassRLS("App-User.1"), `ALTER ROLE "App-User.1" BYPASSRLS;`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.got)
		})
	}
}

func TestBypassRLSResource_CRUD(t *testing.T) {
	t.Parallel()

	testFlagResource(t, flagResourceSpec{
		newResource:  NewBypassRLSResource,
		model:        func(enabled bool) any { return bypassrlsModel{Role: testRole, Enabled: enabled} },
		enableSQL:    `ALTER ROLE "app" BYPASSRLS;`,
		disableSQL:   `ALTER ROLE "app" NOBYPASSRLS;`,
		readSQL:      "SELECT rolbypassrls FROM pg_roles WHERE rolname = $1;",
		column:       "rolbypassrls",
		queryFailure: "Failed to query BYPASSRLS status",
	})
}

func TestBypassRLSResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + `
resource "pgrole_bypassrls" "test" {
  role    = "test"
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_bypassrls.test", "role", "test"),
					resource.TestCheckResourceAttr("pgrole_bypassrls.test", "enabled", "true"),
				),
			},
		},
	})
}
