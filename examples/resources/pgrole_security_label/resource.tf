terraform {
  required_providers {
    pgrole = {
      source  = "registry.terraform.io/manabie-com/pgrole"
      version = "0.0.0"
    }
  }
}

# Create a role for dynamic masking
resource "pgrole_security_label" "masked_user" {
  role  = "app_user"
  label = "MASKED"
}

