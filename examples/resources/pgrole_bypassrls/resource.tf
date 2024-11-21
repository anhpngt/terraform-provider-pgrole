# Manage BYPASSRLS for an existing role.
resource "pgrole_bypassrls" "example" {
  role    = "user1"
  enabled = true
}
