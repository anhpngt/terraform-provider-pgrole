#!/bin/bash
set -e

echo "Initializing PostgreSQL with pgAudit..."

# Enable pgAudit in PostgreSQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create pgaudit extension
    CREATE EXTENSION IF NOT EXISTS pgaudit;
    
    -- Create test users for terraform provider testing
    CREATE ROLE example_user WITH LOGIN PASSWORD 'password';
    CREATE ROLE admin_user WITH LOGIN PASSWORD 'adminpassword' SUPERUSER;
    
    -- Grant necessary privileges
    GRANT ALL PRIVILEGES ON DATABASE postgres TO example_user;
EOSQL

echo "PostgreSQL initialization with pgAudit completed!"