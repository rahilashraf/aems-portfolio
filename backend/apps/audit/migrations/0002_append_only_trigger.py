"""Database-level append-only protection for the audit log (ADR-0006, ADR-0016).

A ``BEFORE UPDATE OR DELETE`` row trigger rejects every change to existing audit rows, whoever
issues it, including raw SQL. ``TRUNCATE`` (a statement-level operation that row triggers do not
see) is denied to the runtime role by privileges (``apps.audit.privileges``); the table owner can
still truncate, as needed by test-database flushing.

Limits: the table owner or a superuser can ``ALTER TABLE ... DISABLE TRIGGER`` or drop it. This
protects against the application and the runtime role, not against database administrators.
"""

from django.db import migrations

CREATE = """
CREATE FUNCTION audit_auditlog_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_auditlog is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_auditlog_append_only
    BEFORE UPDATE OR DELETE ON audit_auditlog
    FOR EACH ROW EXECUTE FUNCTION audit_auditlog_reject_mutation();
"""

DROP = """
DROP TRIGGER IF EXISTS audit_auditlog_append_only ON audit_auditlog;
DROP FUNCTION IF EXISTS audit_auditlog_reject_mutation();
"""


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [migrations.RunSQL(sql=CREATE, reverse_sql=DROP)]
