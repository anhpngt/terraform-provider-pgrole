# pgrole_security_label Resource

Manages PostgreSQL Anonymizer security labels for roles to enable dynamic masking. 

This resource allows you to apply security labels to PostgreSQL roles using the PostgreSQL Anonymizer extension. Security labels are used to mark roles as "MASKED" for dynamic masking purposes, where sensitive data is automatically masked when accessed by those roles.

## Example Usage

```terraform
# Mark a role as masked for dynamic masking
resource "pgrole_security_label" "app_user" {
  role  = "app_user"
  label = "MASKED"
}

# Remove masking from a role (unmask)
resource "pgrole_security_label" "admin_user" {
  role  = "admin_user"
  label = null
}

# Custom security label
resource "pgrole_security_label" "custom" {
  role  = "special_user"
  label = "CUSTOM_LABEL"
}
```

## Argument Reference

The following arguments are supported:

* `role` - (Required) Name of the PostgreSQL role to apply the security label to.
* `label` - (Required) Security label value. Use `"MASKED"` to enable dynamic masking for the role, or `null` to remove the label`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `role` - The name of the role.
* `label` - The current security label value for the role.

## Import

Security label resources can be imported using the role name:

```shell
terraform import pgrole_security_label.example role_name
```

## Prerequisites

Before using this resource, ensure that:

1. The PostgreSQL Anonymizer extension is installed and enabled in your database
2. Dynamic masking is enabled: `ALTER DATABASE your_db SET anon.transparent_dynamic_masking TO true;`
3. The provider has sufficient privileges to manage security labels

## Dynamic Masking Workflow

1. **Enable PostgreSQL Anonymizer**: Install and enable the extension
2. **Set up masking rules**: Define masking rules for sensitive columns
3. **Create masked roles**: Use this resource to mark roles as `"MASKED"`
4. **Grant appropriate permissions**: Ensure masked roles have read access to the data

For more information, see the [PostgreSQL Anonymizer Dynamic Masking documentation](https://postgresql-anonymizer.readthedocs.io/en/latest/dynamic_masking/).

## SQL Operations

This resource performs the following SQL operations:

* **Create/Update**: `SECURITY LABEL FOR anon ON ROLE role_name IS 'label_value';`
* **Delete/Null**: `SECURITY LABEL FOR anon ON ROLE role_name IS NULL;`
* **Read**: Queries `pg_seclabels` system catalog for existing labels