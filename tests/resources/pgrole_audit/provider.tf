terraform {
  required_providers {
    pgrole = {
      source = "local/pgrole"
      version = "1.0.0"
    }
  }
}

provider "pgrole" {
  # Standard PostgreSQL connection parameters
  host     = "localhost"
  port     = 5432
  database = "postgres"
  username = "postgres"
  password = "postgres"
  sslmode  = "disable"
}