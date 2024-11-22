package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
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
