resource "pgrole_security_label" "masked_user" {
  role  = "app_user"
  label = "MASKED"
}

