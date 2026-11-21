#!/usr/bin/env bash
# Development/CI bootstrap: create a least-privilege runtime role and the application database.
#
# The application never connects as the PostgreSQL superuser. The runtime role owns the
# application database so it can run migrations in development. CREATEDB is granted ONLY so
# pytest-django can create its test database; production provisioning must not grant it.
# See docs/adr/0003-tenant-isolation.md (RLS requirements) for the Phase 2 role split.
set -euo pipefail

: "${AEMS_DB_NAME:?AEMS_DB_NAME is required}"
: "${AEMS_DB_USER:?AEMS_DB_USER is required}"
: "${AEMS_DB_PASSWORD:?AEMS_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v app_db="$AEMS_DB_NAME" \
     -v app_user="$AEMS_DB_USER" \
     -v app_password="$AEMS_DB_PASSWORD" <<-'EOSQL'
	CREATE ROLE :"app_user" WITH LOGIN PASSWORD :'app_password'
	    NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS CREATEDB;
	CREATE DATABASE :"app_db" OWNER :"app_user";
	REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
	\connect :"app_db"
	REVOKE ALL ON SCHEMA public FROM PUBLIC;
	ALTER SCHEMA public OWNER TO :"app_user";
EOSQL
