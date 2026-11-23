-- One-time upgrade of a database created before Batch 5, where the runtime role (AEMS_DB_USER,
-- default aems_app) owns the database and every table. Run as a PostgreSQL superuser, then run
-- `migrate` as the owner role with DJANGO_DB_RUNTIME_ROLE set (it grants the runtime privileges).
--
--   psql -U postgres -d aems -v owner_user=aems_owner -v owner_password='...' \
--        -v app_user=aems_app -v app_db=aems -f docker/postgres/upgrade/batch-5-role-split.sql
--
-- See docs/adr/0016-durable-audit-logging.md ("Database roles").
\set ON_ERROR_STOP on
CREATE ROLE :"owner_user" WITH LOGIN PASSWORD :'owner_password'
    NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS CREATEDB;
ALTER DATABASE :"app_db" OWNER TO :"owner_user";
\connect :"app_db"
-- Every object the runtime role owned in this database (tables, sequences, schema) moves to the
-- owner role; the runtime role keeps no ownership.
REASSIGN OWNED BY :"app_user" TO :"owner_user";
ALTER ROLE :"app_user" NOCREATEDB;
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"app_db" TO :"app_user";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"app_user";
