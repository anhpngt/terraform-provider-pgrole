package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	providerConfig = `
provider "pgrole" {
  project_id = "my-project"
  region     = "my-region"
  instance   = "my-instance"
  database   = "my-database"

  username = "my-username"
}
`
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pgrole": providerserver.NewProtocol6WithError(New("test")()),
}

func TestProviderAWSRDSIAMAuthValidation(t *testing.T) {
	resourceConfig := `
resource "pgrole_bypassrls" "test" {
  role    = "test"
  enabled = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "pgrole" {
  username           = "terraform"
  aws_rds_iam_auth   = true
  aws_rds_iam_region = "us-east-1"
}
` + resourceConfig,
				ExpectError: regexp.MustCompile("host is required when aws_rds_iam_auth is enabled"),
			},
			{
				Config: `
provider "pgrole" {
  host               = "mydb.abc123.us-east-1.rds.amazonaws.com"
  username           = "terraform"
  password           = "secret"
  aws_rds_iam_auth   = true
  aws_rds_iam_region = "us-east-1"
}
` + resourceConfig,
				ExpectError: regexp.MustCompile("password must not be set when aws_rds_iam_auth is enabled"),
			},
		},
	})
}
