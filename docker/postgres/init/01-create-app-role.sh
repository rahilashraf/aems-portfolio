#!/usr/bin/env bash
# Development/CI bootstrap: create the owner and runtime roles and the application database.
#
# Two roles (ADR-0016):
# - AEMS_DB_OWNER owns the database and schema and runs migrations. CREATEDB is granted ONLY so
#   pytest-django can create its test database; production provisioning must not grant it.
# - AEMS_DB_USER is the runtime role the application connects as. It owns nothing and cannot
#   create databases. Its table privileges are granted after every `migrate` by
#   apps.audit.privileges (audit table: SELECT and INSERT only).
# Neither role is a superuser. See docs/adr/0016-durable-audit-logging.md.
set -euo pipefail

: "${AEMS_DB_NAME:?AEMS_DB_NAME is required}"
: "${AEMS_DB_OWNER:?AEMS_DB_OWNER is required}"
: "${AEMS_DB_OWNER_PASSWORD:?AEMS_DB_OWNER_PASSWORD is required}"
: "${AEMS_DB_USER:?AEMS_DB_USER is required}"
: "${AEMS_DB_PASSWORD:?AEMS_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v app_db="$AEMS_DB_NAME" \
     -v owner_user="$AEMS_DB_OWNER" \
     -v owner_password="$AEMS_DB_OWNER_PASSWORD" \
     -v app_user="$AEMS_DB_USER" \
     -v app_password="$AEMS_DB_PASSWORD" <<-'EOSQL'
	CREATE ROLE :"owner_user" WITH LOGIN PASSWORD :'owner_password'
	    NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS CREATEDB;
	CREATE ROLE :"app_user" WITH LOGIN PASSWORD :'app_password'
	    NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS NOCREATEDB;
	CREATE DATABASE :"app_db" OWNER :"owner_user";
	REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
	GRANT CONNECT ON DATABASE :"app_db" TO :"app_user";
	\connect :"app_db"
	REVOKE ALL ON SCHEMA public FROM PUBLIC;
	ALTER SCHEMA public OWNER TO :"owner_user";
	GRANT USAGE ON SCHEMA public TO :"app_user";
EOSQL
