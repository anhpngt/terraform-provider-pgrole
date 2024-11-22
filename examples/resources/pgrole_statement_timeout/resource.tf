# Copyright (c) HashiCorp, Inc.

resource "pgrole_statement_timeout" "example" {
  role    = "user1"
  timeout = "30s"
}
