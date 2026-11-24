"""Database-level safeguards that Django cannot declare (ADR-0017).

- Composite foreign keys: a ``MembershipRole`` row must reference a membership **and** a role of
  its own ``organization_id``. A cross-tenant assignment is rejected by PostgreSQL even if the
  application layer is bypassed (raw SQL, ``QuerySet.update()``, data migrations).
- ``rbac_permission``: codes are immutable and rows cannot be deleted (deprecation keeps history).
  ``TRUNCATE`` does not fire row triggers; test-database flushing relies on that.
"""

from django.db import migrations

FORWARD = """
ALTER TABLE rbac_membershiprole
    ADD CONSTRAINT rbac_mrole_membership_same_org_fk
    FOREIGN KEY (membership_id, organization_id)
    REFERENCES organizations_membership (id, organization_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE rbac_membershiprole
    ADD CONSTRAINT rbac_mrole_role_same_org_fk
    FOREIGN KEY (role_id, organization_id)
    REFERENCES rbac_role (id, organization_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION rbac_permission_protect() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'rbac_permission rows cannot be deleted; deprecate them instead'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.code IS DISTINCT FROM OLD.code THEN
        RAISE EXCEPTION 'rbac_permission.code is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER rbac_permission_protect
    BEFORE UPDATE OR DELETE ON rbac_permission
    FOR EACH ROW EXECUTE FUNCTION rbac_permission_protect();
"""

REVERSE = """
DROP TRIGGER IF EXISTS rbac_permission_protect ON rbac_permission;
DROP FUNCTION IF EXISTS rbac_permission_protect();
ALTER TABLE rbac_membershiprole DROP CONSTRAINT IF EXISTS rbac_mrole_role_same_org_fk;
ALTER TABLE rbac_membershiprole DROP CONSTRAINT IF EXISTS rbac_mrole_membership_same_org_fk;
"""


class Migration(migrations.Migration):
    dependencies = [("rbac", "0001_initial")]

    operations = [migrations.RunSQL(FORWARD, REVERSE)]
