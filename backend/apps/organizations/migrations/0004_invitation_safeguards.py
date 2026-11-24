"""Database-level invitation safeguards (ADR-0018), consistent with ``rbac.0002``.

- Composite foreign keys: an ``InvitationRole`` must reference an invitation **and** a role of
  its own ``organization_id``, so a cross-tenant role cannot be attached even with raw SQL.
- ``organizations_invitation``:
  - identity columns (organization, address, kind, inviter, expiry, creation time) never change;
  - only a ``pending`` row can change at all, so acceptance is single-use and an accepted,
    revoked or expired invitation can never be reopened or revoked afterwards;
  - rows are never deleted (history). ``TRUNCATE`` does not fire row triggers; test-database
    flushing relies on that.
"""

from django.db import migrations

FORWARD = """
ALTER TABLE organizations_invitationrole
    ADD CONSTRAINT orgs_invitationrole_invitation_same_org_fk
    FOREIGN KEY (invitation_id, organization_id)
    REFERENCES organizations_invitation (id, organization_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE organizations_invitationrole
    ADD CONSTRAINT orgs_invitationrole_role_same_org_fk
    FOREIGN KEY (role_id, organization_id)
    REFERENCES rbac_role (id, organization_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION organizations_invitation_protect() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'organizations_invitation rows cannot be deleted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'invitation % is % and can no longer change', OLD.id, OLD.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.email IS DISTINCT FROM OLD.email
       OR NEW.is_initial_owner IS DISTINCT FROM OLD.is_initial_owner
       OR NEW.invited_by_id IS DISTINCT FROM OLD.invited_by_id
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'invitation identity columns are immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organizations_invitation_protect
    BEFORE UPDATE OR DELETE ON organizations_invitation
    FOR EACH ROW EXECUTE FUNCTION organizations_invitation_protect();
"""

REVERSE = """
DROP TRIGGER IF EXISTS organizations_invitation_protect ON organizations_invitation;
DROP FUNCTION IF EXISTS organizations_invitation_protect();
ALTER TABLE organizations_invitationrole
    DROP CONSTRAINT IF EXISTS orgs_invitationrole_role_same_org_fk;
ALTER TABLE organizations_invitationrole
    DROP CONSTRAINT IF EXISTS orgs_invitationrole_invitation_same_org_fk;
"""


class Migration(migrations.Migration):
    dependencies = [("organizations", "0003_invitations")]

    operations = [migrations.RunSQL(FORWARD, REVERSE)]
