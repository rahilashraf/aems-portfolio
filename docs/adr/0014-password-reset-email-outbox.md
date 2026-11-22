# ADR-0014: Password-reset email outbox

- **Status:** Accepted
- **Date:** 2026-11-22
- **Amends:** [ADR-0013](0013-authentication-implementation-and-security-events.md) (password-reset
  delivery); Batch 3 scope extension approved by the repository owner

## Context

Under ADR-0013 the password-reset request sent its email synchronously. A known account waited
for the SMTP server and an unknown one did not. Measured locally, a simulated 50 ms SMTP round trip
made known accounts about 50 ms slower, and a stalled server could add up to `EMAIL_TIMEOUT`
(10 s). Response time could therefore reveal whether an account exists.

The fix must remove SMTP from the request without adding Redis, Celery, a persistent worker
service or a general-purpose job queue.

## Decision

### A dedicated outbox table, not a job queue
`accounts.PasswordResetOutbox` stores exactly one kind of work: send this user a password-reset
email. Its fields are:
- `user` (cascade delete);
- `requested_at` and `expires_at`;
- `status`: `pending`, `delivered`, `failed`, `expired` or `cancelled`;
- `attempts` and `next_attempt_at`;
- the lease: `claim_id` and `claimed_until`;
- `last_attempt_at`, `last_failure` (a sanitized category), `delivered_at` and `completed_at`.

A partial unique constraint allows at most one `pending` row per user.

### Payload protection: store no secrets at all
The table has **no recipient address, token, link or message body**. The delivery command:
- reads the user's *current* address;
- generates the reset token from the user's *current* state at send time, with Django's stateless
  HMAC generator bound to `password_changed_at` and `is_active` (ADR-0013).

Consequences:
- **No encryption key to manage**, and no new dependency.
- **A read-only leak of the table** reveals only that a user requested a reset, and when. That is
  personal data, so finished rows are deleted after `retention_seconds` (7 days). Delivered rows
  never held anything more sensitive.
- **Link lifetime.** A token is valid for `PASSWORD_RESET_TIMEOUT` (1 h) from *sending*. The
  request itself expires after `ttl_seconds` (15 min) if it is not sent. A link therefore works at
  most `ttl + PASSWORD_RESET_TIMEOUT` after the request.
- **Address changes.** If the user's address changes between request and delivery, the email goes
  to the new, current address, never to the address the requester typed.

Encrypting a stored token and address was rejected. It would add key management and a decryption
path, and would still keep secrets at rest. Deriving at send time keeps nothing.

### Enumeration-resistant enqueueing
`POST /auth/password/reset/` now:
1. applies the existing per-IP and per-address rate limits (unchanged, for every address);
2. runs **one SQL statement** for every address:
   ```sql
   INSERT INTO accounts_passwordresetoutbox (…)
   SELECT …, u.id, … FROM accounts_user AS u
   WHERE lower(u.email) = %s AND u.is_active AND left(u.password, 1) <> '!'
   ON CONFLICT (user_id) WHERE status = 'pending'
   DO UPDATE SET requested_at = EXCLUDED.requested_at, expires_at = EXCLUDED.expires_at
   ```
   Known and unknown addresses run the same statement in the same round trip; the account lookup
   and the conditional insert happen inside PostgreSQL. There is no synthetic row for unknown
   addresses and no Python branch before the response, apart from the server-side security
   event;
3. answers the same `202` and body.

A database error in the enqueue statement is recorded as `auth.password_reset.enqueue_failed`
(exception class only), and the response is still `202`. If the database is entirely
unavailable, the rate limiter fails first, with the same `500` for every address.

The request contacts no SMTP server: tests use a mail backend that fails if it is even
instantiated, and a real SMTP server that counts connections.

**Why requests cannot create unlimited records:**
- unknown, inactive and password-less addresses insert nothing;
- each user has at most one pending row, and repeated requests refresh it;
- new rows after delivery are bounded by the per-address rate limit (3 per hour by default) and by
  the 7-day retention purge.

So the table is bounded by about *users × rate limit × retention*, and its size is independent of
attacker-chosen addresses.

**Not constant time.** The conditional insert, index and buffer state, and the database can still
differ by small amounts, typically under a millisecond in-process. Only the large SMTP side
channel is removed. No artificial delays were added.

### Delivery command
`python manage.py deliver_password_reset_emails [--batch-size N] [--status]`. Each run:
1. **Expires** unclaimed pending rows past `expires_at` (`auth.password_reset.delivery_expired`).
2. **Claims** one due row at a time:
   - `SELECT … FOR UPDATE SKIP LOCKED` in a short transaction;
   - sets a lease (`claim_id`, `claimed_until = now + lease_seconds`) and increments `attempts`;
   - commits before any network I/O, so **no row lock is held during SMTP**, and concurrent runs
     skip each other's rows instead of waiting.
3. **Re-checks eligibility.** The request is cancelled (`delivery_cancelled`) in two cases:
   - the user is inactive or has an unusable password (`account_ineligible`);
   - the password changed after the request (`superseded`).
4. **Sends** the email, then records the outcome with a compare-and-set on `claim_id`. If the
   lease expired and another run reclaimed the row, the stale outcome is discarded
   (`delivery_lease_lost`).
5. **On failure** records a sanitized category: `recipient_refused`, `smtp_authentication`,
   `connection`, `timeout`, `smtp_error`, `network` or `unexpected`.
   - `recipient_refused` is permanent and fails at once.
   - Other categories retry after `backoff_base * 2^(attempt-1)`, capped at `backoff_cap`
     (60 s, 120 s, … 900 s), up to `max_attempts` (5); then the row is `failed`.
   - Exception messages are never stored or logged, because they can contain the address.
6. **Purges** finished rows older than the retention period.

`--batch-size` is bounded (1–1000), so a run is bounded. The lease must exceed `EMAIL_TIMEOUT`;
the command refuses to run otherwise.

### Delivery guarantees
- **At least once, not exactly once.** If the process dies after the SMTP server accepted a
  message but before the row is marked delivered, the lease expires and the message is sent again.
  Duplicates are bounded by `max_attempts` and `ttl_seconds`.
- **Every copy is an ordinary token.** It expires and is single-use: completing a reset changes
  `password_changed_at`, which invalidates every copy. A test sends a duplicate after a simulated
  crash and verifies that the second link resets the password and the first is then rejected.
- **No send after expiry or invalidation.** Expired rows are never claimed; superseded and
  ineligible requests are cancelled.

### Operations (deployment deferred)
- **There is no scheduler in Batch 3.** Something must run the command regularly, for example
  every minute:
  - a cron job or systemd timer:
    `docker exec aems-api python manage.py deliver_password_reset_emails`;
  - or a Kubernetes `CronJob` running the image with
    `python manage.py deliver_password_reset_emails`.

  Choosing and deploying it is deferred to deployment work.
- **If nothing runs it:**
  - requests are still accepted with `202`, but **no email is sent**;
  - pending rows expire after 15 minutes and are purged later;
  - nothing is delivered automatically when the scheduler starts again: expired requests are
    discarded and the user must ask again.
- **Monitoring:** `deliver_password_reset_emails --status` prints JSON with:
  - counts per status, `pending_due` and `pending_claimed`;
  - `oldest_pending_age_seconds`;
  - counts per failure category.

  It contains no user ids, addresses or tokens. A growing `pending_due` or
  `oldest_pending_age_seconds` means delivery is not running. Per-message events
  (`email_delivered`, `delivery_failed`, `delivery_expired`, `delivery_cancelled`) go to the
  security log with the user and outbox ids only.
- **Access:** the table is reached only by backend code and the command. There is no API endpoint,
  serializer or admin registration. Batch 3 uses one database role, so database-level separation
  is not provided; that is a deployment hardening item.

### Security events (Batch 5 interface)
- `auth.password_reset.requested` (`queued` true/false)
- `auth.password_reset.enqueue_failed`
- `auth.password_reset.email_delivered`
- `auth.password_reset.delivery_failed` (`category`, `retry_scheduled`)
- `auth.password_reset.delivery_expired`
- `auth.password_reset.delivery_cancelled` (`reason`)
- `auth.password_reset.delivery_lease_lost`

They are emitted through `apps.core.security_events` and carry no addresses, tokens or exception
messages. ADR-0013 used `delivery_failed` for synchronous send failures; it is now emitted by the
command.

## Consequences
- **Reset response time** no longer depends on the mail server.
- **Email delivery** depends on an operator-run schedule, which is not yet deployed.
- **Sensitive data at rest:** only user ids and timestamps, kept for at most 7 days.
- **Duplicate emails** are possible after a crash. They are bounded, and each link stays
  single-use.

## Alternatives considered
- *Background thread in the web process*: emails are lost on restart, and threads would leak into
  every gunicorn worker.
- *Celery/Redis*: excluded by the Batch 3 scope and the Phase 1 plan.
- *Synthetic rows for unknown addresses*: unbounded growth driven by attacker-chosen addresses.
- *Padding responses with sleeps*: hides nothing reliably, wastes workers, and was excluded.
