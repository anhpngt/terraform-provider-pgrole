locals {
  users = toset(["jane.doe@example.com", "john.doe@example.com"])
}

resource "google_sql_user" "users" {
  for_each = local.users

  name     = each.value
  instance = "my-instance"
  type     = "CLOUD_IAM_USER"

  # New users, and the resource below for them, are created before the users
  # that left are deleted: a user that cannot be deleted yet does not hold up
  # the others.
  lifecycle {
    create_before_destroy = true
  }
}

# Depends on the user, so Terraform destroys it first: by the time the user is
# deleted, the role holds no privileges and PostgreSQL lets it be dropped.
resource "pgrole_revoke_on_destroy" "users" {
  for_each = google_sql_user.users

  role = each.value.name
}
