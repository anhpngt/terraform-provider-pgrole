provider "pgrole" {
  # AWS RDS connection parameters, authenticating with IAM
  host               = "mydb.abc123.us-east-1.rds.amazonaws.com"
  port               = 5432
  database           = "postgres"
  username           = "terraform" # must be granted the rds_iam role
  aws_rds_iam_auth   = true
  aws_rds_iam_region = "us-east-1"
}
