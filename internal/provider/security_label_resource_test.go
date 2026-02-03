package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSecurityLabelResource(t *testing.T) {
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

func TestAccSecurityLabelResourceRemoveLabel(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with MASKED label
			{
				Config: providerConfig + `
resource "pgrole_security_label" "test" {
  role  = "test_role2"
  label = "MASKED"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_security_label.test", "role", "test_role2"),
					resource.TestCheckResourceAttr("pgrole_security_label.test", "label", "MASKED"),
				),
			},
			// Remove the label (set to null)
			{
				Config: providerConfig + `
resource "pgrole_security_label" "test" {
  role  = "test_role2"
  label = null
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pgrole_security_label.test", "role", "test_role2"),
					resource.TestCheckNoResourceAttr("pgrole_security_label.test", "label"),
				),
			},
		},
	})
}
