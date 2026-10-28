#!/bin/bash
# Runs once, on the first start of an empty data volume (postgres image entrypoint).
# Creates the CloudPulse role and database, then applies the schema and default settings.
set -euo pipefail

: "${CLOUDPULSE_DB:=cloudpulse}"
: "${CLOUDPULSE_DB_USER:=cloudpulse}"
: "${CLOUDPULSE_DB_PASSWORD:?CLOUDPULSE_DB_PASSWORD must be set}"
: "${CLOUDPULSE_ADMIN_PASSWORD:?CLOUDPULSE_ADMIN_PASSWORD must be set}"

SQL_DIR=/docker-entrypoint-initdb.d/sql

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
     -v db="$CLOUDPULSE_DB" -v usr="$CLOUDPULSE_DB_USER" -v pw="$CLOUDPULSE_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'usr', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'usr') \gexec
SQL

as_app() {
  psql -v ON_ERROR_STOP=1 \
    --username "$CLOUDPULSE_DB_USER" --dbname "$CLOUDPULSE_DB" "$@"
}

as_app -f "$SQL_DIR/10-schema.sql"
as_app -f "$SQL_DIR/20-settings.sql"

# Initial administrator; bcrypt via pgcrypto so no hash is stored in the repository
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$CLOUDPULSE_DB" \
     -v pw="$CLOUDPULSE_ADMIN_PASSWORD" -v usr="$CLOUDPULSE_DB_USER" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO public.cloudpulse_users (username, email, full_name, hashed_pw, is_active, is_admin)
VALUES ('admin', NULL, 'Administrator', crypt(:'pw', gen_salt('bf', 12)), TRUE, TRUE)
ON CONFLICT (username) DO NOTHING;
DROP EXTENSION pgcrypto;
SQL

echo "CloudPulse database '$CLOUDPULSE_DB' initialised."
