# ADR-0018: Invitations and organization onboarding (Batch 7)

- **Status:** Accepted
- **Date:** 2026-11-24
- **Implements:** plan §4.6 and §5.3; completes the provisioning lifecycle of
  [ADR-0015](0015-organizations-and-tenancy-implementation.md) and the Batch 7 dependencies of
  [ADR-0017](0017-organization-rbac-implementation.md); invitation authentication per
  [ADR-0004](0004-authentication-and-session-management.md)

## Context

Organizations are created `provisioning` by platform administrators, with seeded Owner, Admin and
Member roles but no Owner (Batch 6). Batch 7 adds:
- invitations, the only way people join an organization;
- the initial Owner invitation, whose acceptance is the only `provisioning → active` transition.

An invitation link is a bearer credential, and accepting it can grant any role, including Owner.
It must therefore obey the same delegation, Owner-invariant, concurrency and audit rules as
Batch 6.

## Decisions

### Data model (`organizations.0003`, `organizations.0004`)
- **`Invitation`** (tenant-scoped, organization immutable). Fields:
  - `email`, stored normalized (ADR-0008);
  - `is_initial_owner` and `status` (`pending`, `accepted`, `revoked` or `expired`);
  - `token_hash` (SHA-256 hex, NULL until the first email is sent) and `token_issued_at`;
  - `invited_by`, `expires_at`, `accepted_at`, `accepted_by`, `revoked_at`, `revoked_by`;
  - timestamps.
- **`Invitation` constraints:**
  - `organizations_invitation_one_pending_per_email`: one pending invitation per organization and
    address;
  - `organizations_invitation_one_pending_initial_owner`: one pending initial Owner invitation
    per organization;
  - a unique, well-formed digest;
  - a lowercase, non-blank address;
  - expiry after creation;
  - `organizations_invitation_state_consistent`: timestamps and actors match the status, and
    `accepted_at < expires_at`.
- **`InvitationRole`** (tenant-scoped): unique (invitation, role). Composite foreign keys on
  `(id, organization_id)` reject a role of another organization even with raw SQL, as Batch 6
  does for `MembershipRole`.
- **Trigger `organizations_invitation_protect`:**
  - only a `pending` row can change, so accepted, revoked and expired invitations are final and
    acceptance is single-use at the database level;
  - organization, address, kind, inviter, expiry and creation time never change;
  - rows are never deleted.
- **Deleting roles.** `rbac.services.delete_role` refuses (409 `role_in_use`) to delete a role
  that a pending invitation would grant.
- **`InvitationEmail`:** the delivery outbox (below). It holds no address, token, link or body.

### Tokens
- **Generation and storage.** `secrets.token_urlsafe(32)` gives 256 bits. Only
  `sha256(token)` is stored. Lookups go through the unique digest index, followed by
  `hmac.compare_digest`. Malformed tokens are rejected before any query.
- **Issued at send time.** The delivery command generates the token when it sends the email and
  stores its digest. An invitation therefore has no usable token until an email has gone out.
- **Rotation.** Every send rotates the token, so after a resend (for example after a crash) only
  the latest link works.
- **Lifetime.** Default 7 days (`AEMS_INVITATION_TTL_SECONDS`). Tokens are single use and
  revocable.
- **Never exposed.** Tokens and digests never appear in:
  - API responses (list, detail, platform);
  - audit metadata or logs;
  - the admin, which excludes the digest;
  - exception messages.

  The path redaction from Batch 2 keeps `/invitations/{token}/` out of every log line (route
  patterns only, Django request logs redacted, no gunicorn access log).
- **Links.** The token travels in the URL fragment
  (`{AEMS_FRONTEND_BASE_URL}/invitations/accept#token=…`), which browsers never send to servers
  or in `Referer`.
- **HTTPS in production.** Production settings refuse a frontend origin that is not `https://`,
  which also protects password-reset links.
- **Public responses** carry `Cache-Control: no-store, private`, `Pragma: no-cache` and
  `Referrer-Policy: no-referrer`.

### Member invitations (tenant API)
| Route | Permission |
|---|---|
| `GET /organizations/{org_id}/invitations/` | `invitations.manage` |
| `POST /organizations/{org_id}/invitations/` (`email`, `role_ids`) | `invitations.manage` + delegation |
| `POST /organizations/{org_id}/invitations/{id}/revoke/` | `invitations.manage` + delegation |

**Creation** follows the Batch 6 protocol: lock the organization, then reload the actor's
permissions from the database. Requests are rejected in this order:
1. an inactive organization (409);
2. missing `invitations.manage` (403);
3. invalid roles, 1–20 of this organization (400);
4. roles whose permissions the actor does not hold (403 `delegation_not_allowed`), or the Owner
   role for a non-Owner (403 `owner_role_restricted`);
5. an address that already belongs to a member (409 `already_member`), which also blocks
   inviting oneself;
6. an unexpired pending invitation for the address (409 `invitation_already_pending`; revoke it
   first). An expired one is marked `expired` and replaced.

Existing users of other organizations can be invited. The invitation and its outbox row commit
together with `invitation.created`.

**Listing** returns safe metadata only:
- `status` (pending invitations past their expiry report `expired`);
- roles, inviter id, timestamps and `delivery_status`.

Filter by `status`; ordering by creation or expiry with an id tie-breaker.

**Revocation:**
- Only `pending` invitations can be revoked (409 `invitation_not_pending`). An accepted invitation
  can never be revoked, and its membership is managed through the member APIs.
- The actor needs authority over the invitation's roles; Owner invitations need an Owner.
- Revoking changes nothing about the actor's own permissions.

### Initial Owner onboarding (platform)
- **Creation.** `POST /platform/organizations/` now requires `initial_owner_email`. One
  transaction creates:
  - the `provisioning` organization;
  - its system roles;
  - the initial Owner invitation (Owner role only) and its outbox row;
  - the audit records `organization.created` and `invitation.initial_owner_issued`.

  If any step fails, nothing is created. The creator does not become a member.
- **Reissue and revoke:**
  - `GET`, `POST /platform/organizations/{id}/initial-owner-invitation/` views the pending
    invitation, or revokes it and issues a new one;
  - `POST …/revoke/` revokes it.

  Both work for provisioning organizations only (409 `organization_not_provisioning`), including
  organizations created before Batch 7, which have none.
- **Permissions.** Changes require the new Django model permission
  `organizations.manage_initial_owner_invitation`, re-checked from the database inside the
  transaction; viewing requires `view_organization`. Staff status alone is not enough.
- **No generic platform RBAC** is added.

### Preview (`GET /invitations/{token}/`, public, allowlisted)
- **Returns:** the organization name, the masked address (`a****@example.org`), status, expiry and
  the next step.
- **Next step:** `accept` when the caller is signed in as the invitee, otherwise
  `sign_in_or_create_account`. Whether an account exists is not revealed.
- **Unusable tokens all get the same 404 `invitation_invalid`:**
  - unknown or malformed;
  - expired, revoked or accepted;
  - superseded by a newer email;
  - the organization is in the wrong state.
- **Rate limit.** Preview and acceptance are limited per client IP (`invitation_ip`, 60 per
  5 minutes; 429 with `Retry-After`).

### Acceptance (`POST /invitations/{token}/accept/`, public, allowlisted)
- **The invited address has an account:**
  - the caller must be signed in as that account (bearer token);
  - an anonymous caller gets 401 `sign_in_required`, another account 403
    `invitation_email_mismatch`;
  - a password or name is never accepted on this path (400).
- **No account exists:**
  - the caller sends `full_name` and `password`, validated with the existing validators and
    hashed with Argon2;
  - the account is created with the invitation's address, and `password_changed_at` is set;
  - `email` and privilege fields (`is_staff`, `is_superuser`, `is_active`) are rejected as unknown
    keys;
  - a signed-in caller cannot create a second account (403);
  - holding the token proves control of the mailbox.
- **Registration race.** If someone registers the address at the same moment, the unique index
  decides: acceptance answers 401 `sign_in_required` and creates nothing.
- **One transaction:**
  1. lock or insert the user row;
  2. lock the organization;
  3. lock the invitation;
  4. re-check token, status and expiry (with `now` read inside the lock) and the organization
     state;
  5. re-validate authority (below);
  6. refuse an existing membership (409 `already_member`);
  7. create the active membership and its role assignments (`assigned_by` = inviter);
  8. mark the invitation accepted;
  9. write the audit records;
  10. for the initial Owner, activate the organization.

  Any failure rolls everything back: no account, membership, role or activation without its
  accepted invitation and audit records. The response returns the organization, membership,
  roles and `account_created`; no session is issued, and the user then signs in normally.
- **Rejected acceptances** are recorded after rollback as independent security events
  (`invitation.accept_rejected`, with the error code as `reason`).

### Authority re-validation (fail closed)
A member invitation is accepted only if its **inviter could still issue it**. The check runs under
the organization lock, against current state: the inviter must still be an active member holding
`invitations.manage` and every permission the invited roles confer **now**, and be an Owner if the
Owner role is included.
- If the inviter has been suspended, removed or demoted, or a role gained a permission the
  inviter lacks, acceptance fails with 409 `invitation_authority_revoked` and nothing changes.
- The invitation stays pending; a current manager can revoke it and invite again.
- So an old invitation can never grant more than a current authorized member could grant.

An initial Owner invitation must grant exactly the Owner role, otherwise it fails closed.

### Activation invariant
- **The only path.** `provisioning → active` happens only in the acceptance of the pending initial
  Owner invitation, and only after the Owner membership and role exist in the same transaction
  (`organization.activated`).
- **No other path.** Platform `PATCH` still refuses activation (409), and there is no manual or
  bypass endpoint.
- **Suspended organizations** are not reactivated: invitations to them are unusable, and their
  emails are cancelled.
- **Upgrade from Batch 6.** No migration activates an organization or creates an invitation.
  Provisioning organizations without an invitation get one through the platform reissue
  endpoint.

### Email delivery (`InvitationEmail`, `manage.py deliver_invitation_emails`)
Modelled on the password-reset outbox (ADR-0014), but not a general job queue:
- **Queued, not sent.** Creating an invitation inserts the outbox row in the same transaction. No
  SMTP connection is made in a request or in a database transaction, and a rolled-back invitation
  never sends email.
- **Claiming.** The command claims due rows with `SELECT … FOR UPDATE SKIP LOCKED` under a lease,
  committing before any network I/O.
- **Delivery.** For each row, it:
  1. re-checks that the invitation is still deliverable (otherwise `delivery_cancelled` with
     `not_pending`, `expired` or `organization_unavailable`);
  2. issues the token in a short transaction that confirms the lease;
  3. sends the email: organization name, link, expiry, and sign-in or account-creation
     instructions, never a password.
- **Outcomes** are recorded with a compare-and-set on the lease:
  - `email_delivered`, only when the SMTP server accepted the message (never on queueing);
  - `delivery_failed`, with a sanitized category only;
  - `delivery_lease_lost`, a security event.
- **Retries.** Exponential backoff (60 s doubling, capped at 15 min, 5 attempts). A refused
  recipient fails at once. The invitation itself is unaffected, and managers can revoke and
  reissue.
- **Delivery status.** Exposed as `delivery_status` in the APIs. `--status` prints counts only.
- **Scheduling.** Run the command regularly, like `deliver_password_reset_emails`.

### Lock order (extends ADR-0017)
**user row → organization row → invitation row → new membership and role rows.**
- **Acceptance by an existing account** locks the user first, as global deactivation does, so the
  two serialize on the user row. A deactivated account cannot be granted a membership.
- **Acceptance with a new account** inserts the user row first. It is invisible to, and cannot be
  locked by, any other transaction until commit, which is the equivalent first step.
- **Creation, revocation, reissue and every RBAC mutation** start at the organization row. So
  invitations serialize with member, role and status changes and with deactivations of that
  organization.
- **Delivery** locks only its outbox row and updates the invitation's digest in a separate short
  transaction. It never holds an organization lock, so it cannot deadlock with them.

Concurrency tests on real PostgreSQL threads cover every pairing listed under Testing; none
deadlocks.

### Audit events
In the mutation transaction:
- `invitation.created`, `invitation.initial_owner_issued`, `invitation.revoked`,
  `invitation.expired`, `invitation.accepted`;
- `rbac.membership.created`, `rbac.membership.roles_assigned`, `rbac.owner.granted`;
- `organization.activated`;
- `auth.account.created` (`reason: invitation`);
- `invitation.email_delivered`, `invitation.delivery_failed`, `invitation.delivery_cancelled`.

Independent:
- `invitation.accept_rejected`;
- `invitation.delivery_lease_lost`;
- `auth.rate_limited` (`scope: invitation`).

Invitation events belong to the organization's history. New metadata keys are `invitation_id`,
`initial_owner` and `account_created`; addresses, tokens, digests, links and passwords are never
recorded. The actor's address appears only as the existing `actor_email` snapshot (ADR-0016).

### Testing
- **Coverage:** creation, listing and revocation rules; preview and acceptance for existing and
  new accounts; delegation re-validation; onboarding and activation; delivery; database
  safeguards; the Batch 6 upgrade and reversibility.
- **Concurrency** (real PostgreSQL threads):
  - double acceptance, with new and with existing accounts;
  - acceptance against revocation, account registration, deactivation, initial Owner reissue and
    a role change of the inviter;
  - concurrent invitations for the same address;
  - three simultaneous initial Owner acceptances;
  - a mixed deadlock check.
- **Expiry boundary:** accepted one microsecond before `expires_at`, refused at it.
- **Audit:** failure injection rolls back acceptance, activation and creation; no secrets in
  audit rows or logs.
- **Authorization:** the matrix and route-coverage meta-test include the invitation endpoints;
  the public routes are explicit token-scoped exceptions.
- **CI:** the production image onboards the CI organization from the Mailpit email.

## Deviations and decisions for review
1. **Tokens are issued when the email is sent**, not at creation, and every send rotates the token.
   No raw token is stored, at the cost that only the latest email's link works.
2. **Unusable tokens are indistinguishable** (one 404) in preview and acceptance, including
   expired ones. The token holder does not learn why.
3. **Account existence** is never revealed by the preview. Acceptance necessarily tells the token
   holder (sign in or create an account), which plan §4.6 allows.
4. **Stale inviter authority fails closed** and leaves the invitation pending (409), rather than
   revoking it automatically.
5. **Revoking a member invitation** requires authority over its roles, mirroring Batch 6.
6. **Duplicate handling:** one pending invitation per address (409 until revoked); expired pending
   invitations are marked `expired` when replaced. Their stored status otherwise stays `pending`
   until then, while the API reports `expired`.
7. **No session on acceptance:** the new member signs in with the normal login flow.
8. **Production requires an `https://` frontend origin** (`AEMS_FRONTEND_BASE_URL`); the deploy
   check and CI set one.
9. **`suspended → active` reactivation is still not available.** The plan expects an Owner-checked
   reactivation, but the later Batch 6 and 7 restrictions forbid new activation paths; flagged for
   review.

## Deferred (Batch 8 and later)
- Resending an invitation email without reissuing it; retention or purge of old invitations and
  outbox rows.
- An owner-verified `suspended → active` reactivation, if approved.
- Batch 8 security hardening:
  - an attack suite against the public token routes (brute force, timing, enumeration);
  - SECURITY.md guidance for operating both delivery commands;
  - deliverability configuration (SPF, DKIM).
- Platform RBAC administration (still not approved).
