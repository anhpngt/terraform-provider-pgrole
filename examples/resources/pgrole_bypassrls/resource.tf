# Copyright (c) HashiCorp, Inc.

resource "pgrole_bypassrls" "example" {
  role    = "user1"
  enabled = true
}
