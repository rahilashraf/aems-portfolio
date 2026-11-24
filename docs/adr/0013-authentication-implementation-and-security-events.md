# ADR-0013: Authentication implementation and the security-event boundary

- **Status:** Accepted
- **Date:** 2026-11-22
- **Implements:** [ADR-0004](0004-authentication-and-session-management.md),
  [ADR-0008](0008-email-identity-normalization.md);
  completes the Batch 3 transition described in [ADR-0012](0012-api-access-control-enforcement.md)

## Context

Batch 3 implements accounts and authentication. Implementing ADR-0004 required concrete decisions it
did not fix. It also exposed a dependency on audit persistence, which is scheduled for Batch 5.

## Decisions

### Identity
- **User model:** `accounts.User` (`AbstractBaseUser` + `PermissionsMixin`) with:
  - UUIDv4 primary key, normalized `email`, `full_name`;
  - `is_active`, `is_staff`, `is_superuser`;
  - `date_joined`, `last_login`, `password_changed_at`.
- **Email normalization:** NFKC, then trim, then lowercase. NFKC runs before trimming so that
  ideographic spaces become trimmable.
- **Uniqueness:** enforced by `UniqueConstraint(Lower("email"), name="accounts_user_email_ci_uniq")`.
  Creation runs in a savepoint; a violation of that named constraint becomes
  `409 email_already_registered`, and other integrity errors propagate.
- **Migration ordering:** `AUTH_USER_MODEL` was set before the first auth migration, so `auth_user`
  never exists. `auth_group` and `auth_permission` do exist, for `PermissionsMixin` and the admin.
- **Silenced check:** `auth.W004` is silenced, because Django's check cannot see functional unique
  constraints.

### Passwords
- **Hashing:** Argon2id first; PBKDF2 kept for verification only.
- **Validators:** user-attribute similarity, minimum length (`DJANGO_PASSWORD_MIN_LENGTH`, default
  12; production refuses less), maximum length 128 (bounds hashing cost), common passwords, numeric.
- **Change and reset** both run in one transaction that:
  - locks the user row;
  - sets the password and `password_changed_at`;
  - revokes every session.

  Change then issues a fresh session; reset does not sign the user in.

### Tokens and sessions
- **Signing:** SimpleJWT `AccessToken`/`RefreshToken` primitives, HS256 with `DJANGO_JWT_SIGNING_KEY`.
  Production refuses a key that is short, a placeholder, or equal to `SECRET_KEY`.
- **Claims:** `sub`, `sid`, `jti`, `iat`, `exp`, `type`; `iss`/`aud` are enforced when configured.
- **Lifetimes:** access tokens last 10 minutes. Refresh tokens last 7 days, capped at the session's
  absolute 30-day lifetime.
- **SimpleJWT features not used:** its blacklist app and its rotation; `AuthSession` replaces both.
- **Stored state:** `AuthSession` stores only an HMAC of the current refresh `jti`. Plaintext tokens
  are never stored.
- **Per-request validation.** Every authenticated request loads the session and user, and rejects:
  - revoked or expired sessions;
  - inactive users;
  - tokens with `iat` earlier than `password_changed_at`.

  Revocation therefore takes effect immediately.
- **Rotation** follows plan §4.2. A row lock acts as compare-and-swap: one concurrent refresh wins,
  and the others are treated as replay, which revokes the family. No grace period.
- **Replay revocation commits before the 401.** The rotation service never raises inside its
  transaction; it returns an outcome that the view converts into a generic 401.
- **Refresh cookie:** `aems_refresh`, `HttpOnly`, `Secure` (production enforces this),
  `SameSite=Strict`, `Path=/api/v1/auth/`. The refresh token is never in a response body.

### CSRF
- **Enforced on refresh**, and on logout when the refresh cookie is present, using Django's
  `CsrfViewMiddleware` checks: `X-CSRFToken` must match the cookie, and Origin/Referer must match.
- **`GET /api/v1/auth/csrf/`** issues the `csrftoken` cookie (readable, `SameSite=Strict`).
- **Login is not CSRF-checked.** It sets no state an attacker can exploit, and login CSRF is
  mitigated because the endpoint accepts only `application/json`: cross-site forms get 415, and
  cross-origin JSON needs a CORS preflight that only allowlisted origins pass.

### Public endpoints and access control
- **Public auth endpoints:** csrf, login, refresh, logout, password reset request and confirm. Each
  is allowlisted and uses no authentication classes, but still sends a `Bearer` challenge on 401.
- **Logout is public**, so an expired access token cannot block it. It accepts the refresh cookie
  (with CSRF) or a still-valid bearer token.
- **Logout binds the token to its session (AEMS-011).** Only a signature-valid, unexpired token
  identifies a session, and the session is looked up by **both** signed claims, `sid` and `sub`.
  A client-supplied session id is never acted on alone:
  - a cookie whose `sid` names another user's session revokes nothing and records
    `auth.session.owner_mismatch`, since that can only follow a signing-key leak or a defect;
  - any request carrying the refresh cookie must pass CSRF, even if the cookie is invalid;
  - invalid, expired or unknown cookies revoke nothing but are still cleared. The response is
    always 204, so repeated logouts are harmless;
  - if the cookie identifies no session, a still-valid bearer token is used. It is resolved the same
    way (`sid` + `sub`, session and user still usable).
- **Defaults:** `IsAuthenticated` and `SessionJWTAuthentication`. Unauthenticated requests to
  protected endpoints receive `401 not_authenticated` with `WWW-Authenticate: Bearer realm="api"`.

### Abuse protection
- **Counters:** PostgreSQL `AuthRateLimit` with atomic `INSERT … ON CONFLICT … RETURNING` counters,
  keyed by HMAC digests and using fixed windows. Scopes:
  - login per IP, per account and per IP+account;
  - refresh per IP;
  - password reset per IP and per account;
  - reset confirmation per IP;
  - password change per user.
- **Account backoff:** `AuthBackoff`. From the 5th consecutive failure the account digest is locked
  for 30 s, doubling each time up to 15 minutes. It applies to unknown emails too, so it reveals
  nothing.
- **Enumeration resistance.** Unknown, wrong-password and inactive logins give identical responses,
  and Django's backend hashes for unknown users too. Password reset always answers 202.
- **DRF throttles are not used.** The atomic database limiter supersedes them; the plan listed them
  only as a coarse outer layer.
- **Client IP:** `REMOTE_ADDR`, unless `DJANGO_TRUSTED_PROXY_COUNT` is set.

### Password-reset links
- **Token location:** the token is placed in the URL **fragment**
  (`…/reset-password#uid=…&token=…`), which browsers never send to servers or in `Referer` headers.
- **Token validity:** Django's generator, additionally bound to `password_changed_at` and
  `is_active`. It expires after `PASSWORD_RESET_TIMEOUT` (1 hour) and is single-use.

### Password-reset delivery (AEMS-010, superseded in part by ADR-0014)
Review correction AEMS-010 first made delivery failures invisible to clients: the response is the
same `202`, body and headers whether or not the account exists and whether or not sending works.
Failures are reported as sanitized `auth.password_reset.delivery_failed` events, never with the
address, the exception message or the token.

That fix still sent mail **synchronously** inside the request. Measured locally, known accounts
were about 50 ms slower with a simulated 50 ms SMTP round trip, and up to `EMAIL_TIMEOUT` (10 s)
slower with a stalled server, so response time still revealed account existence.
[ADR-0014](0014-password-reset-email-outbox.md) removes SMTP from the request: requests only
enqueue, and `deliver_password_reset_emails` sends. The sanitized-failure and generic-response
rules above still apply, now in the delivery command. An earlier `make_password(None)` "dummy
work" call was removed: it hashes nothing, so it never balanced the two paths.

### Platform admin
- **Access:** staff only, at a path set by `DJANGO_ADMIN_URL`. The admin login uses the same rate
  limits and backoff as the API.
- **Password hashes** are never rendered. Admin password changes revoke all sessions.
- **No escalation:** only superusers may change `is_staff`, `is_superuser`, groups or permissions.
- **Deactivation** goes through `services.deactivate_user`, which revokes sessions. It is the only
  deactivation path; there is deliberately no public API endpoint for it.

### Security-event boundary (Batch 5 dependency; implemented by ADR-0016)
Batch 5 replaced this boundary as described in [ADR-0016](0016-durable-audit-logging.md):
mutation events are written by `audit.record()` inside their transactions; failure events by
`audit.record_security_event()` in their own; `apps.core.security_events` is now the log layer
only. The original Batch 3 text follows.
The approved plan records `auth.refresh_reuse_detected` as an audit event in the replay
transaction, with a test asserting the event exists. Durable audit persistence (`AuditLog`) is
Batch 5. Adding an audit schema in Batch 3 would implement part of Batch 5 early, so it is not done.

Instead, `apps.core.security_events` defines the interface Batch 5 will implement:
- **Mutation events** use `record_after_commit`: emitted only if the transaction commits.
- **Failure and security events** use `record_security_event`: emitted immediately and never lost to
  a rollback. Replay detection records its event *after* the revocation commits.
- **Conventions:** dotted past-tense names (`auth.login.succeeded`, `auth.refresh.reuse_detected`),
  an `outcome`, identifiers only (`user_id`, `session_id`, `client_ip`, `subject_digest`), and never
  secrets.
- **Current sink:** the structured security log (`aems.security`).

**Not implemented until Batch 5:** durable, queryable, append-only persistence of these events. Until
then they exist only in logs. Batch 3 tests assert that the revocation is durably committed and the
event is emitted; nothing claims an audit record is stored.

## Batch 5 integration requirements
- Register a durable sink, or replace the after-commit path, so **mutation events are inserted inside
  the same transaction** as the change. That replaces `record_after_commit` for audited actions.
- Persist **failure events in their own short transaction**, as now.
- Keep the event names and fields stable: migrations, reports and alerting will depend on them.

## Batch 6 integration requirements
- `services.deactivate_user` must lock every active organization in which the user is an active
  Owner (ascending id) and refuse if any would be left without another active Owner (plan §6.3)
  **before** clearing `is_active`. The admin already routes deactivation through this service.
- Password-reset and session revocation remain account-level and need no organization checks.

## Consequences
- One indexed session lookup per authenticated request.
- Password-reset email delivery leaves the request path (ADR-0014). It then depends on regularly
  running `deliver_password_reset_emails`, which is not yet scheduled anywhere.
- The production image does not yet serve the admin's static files; that is a deployment concern.
- Security events are not yet durable (Batch 5).
