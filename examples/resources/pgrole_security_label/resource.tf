resource "pgrole_security_label" "masked_user" {
  role  = "app_user"
  label = "MASKED"
}

# With PostgreSQL Anonymizer 1.x, a masked role keeps the privileges that
# dynamic masking gave it when its label is removed, and cannot be dropped.
# revoke_on_destroy takes them back when this resource is destroyed.
resource "pgrole_security_label" "masked_user_to_be_dropped" {
  role              = "jane.doe@example.com"
  label             = "MASKED"
  revoke_on_destroy = true
}
