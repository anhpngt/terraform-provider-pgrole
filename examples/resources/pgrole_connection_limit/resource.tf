resource "pgrole_connection_limit" "example" {
  role             = "user1"
  connection_limit = 200
}
