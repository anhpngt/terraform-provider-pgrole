resource "pgrole_audit" "example" {
  role            = "example_user"
  audit_log_option = "all"
}