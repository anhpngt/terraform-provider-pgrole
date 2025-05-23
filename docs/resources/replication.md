---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pgrole_replication Resource - pgrole"
subcategory: ""
description: |-
  Manage REPLICATION status for an existing role. See PostgreSQL ALTER ROLE https://www.postgresql.org/docs/current/sql-alterrole.html.
---

# pgrole_replication (Resource)

Manage REPLICATION status for an existing role. See PostgreSQL [ALTER ROLE](https://www.postgresql.org/docs/current/sql-alterrole.html).

## Example Usage

```terraform
resource "pgrole_replication" "example" {
  role    = "user1"
  enabled = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `role` (String) Name of the role.

### Optional

- `enabled` (Boolean) Whether to enable REPLICATION for the role.

## Import

Import is supported using the following syntax:

```shell
# replication can be imported by specifying the role.
terraform import pgrole_replication.example role
```
