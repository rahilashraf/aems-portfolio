# ADR-0004: Authentication and session management

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

The browser frontend (Next.js) and future non-browser clients (e.g. paper-exam scanning stations)
need to authenticate. Requirements: refresh-token rotation with replay detection, CSRF protection
for cookie-authenticated endpoints, no access tokens in `localStorage`, immediate effect of
password change, logout and deactivation, and abuse protection that is correct under concurrency.

## Decision

- **Access token**: short-lived (10 min) JWT in the response body, sent as `Authorization: Bearer`,
  held in memory by the browser client (never `localStorage`/`sessionStorage`). Claims include
  `sid` (server session id) and `iat`.
- **Refresh token**: JWT in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to
  `/api/v1/auth/`, never exposed to JavaScript or returned in a body.
- **Server-side session (token family)** `AuthSession` storing the hash of the single currently
  valid refresh `jti`. Rotation is a compare-and-swap under `SELECT … FOR UPDATE`: the matching
  token is exchanged for a new pair; a non-matching (previously rotated) token is treated as
  **replay** and revokes the entire family, with an audit event.
- **Per-request validation** of access tokens checks the session and user state (one indexed
  query), so logout, password change, reuse revocation, and deactivation take effect immediately.
- **Password change/reset** revoke all sessions and set `password_changed_at`; tokens with an
  older `iat` are rejected as a second line of defence.
- **CSRF**: cookie-authenticated endpoints (refresh, logout) enforce Django CSRF (double-submit
  token + Origin/Referer validation). Bearer-only endpoints are not CSRF-susceptible.
- **Abuse protection**: an atomic PostgreSQL limiter (`INSERT … ON CONFLICT DO UPDATE … RETURNING`)
  keyed by HMAC digests of IP and normalized email, with temporary exponential per-account backoff.
  DRF throttles are kept only as a coarse outer layer because their cache read-modify-write is
  not atomic.
- **Invitations**: existing users must be authenticated as the invited email to accept.
- SimpleJWT supplies token encoding/validation primitives; its blacklist app is not used because
  the session model supersedes it.

## Alternatives considered

- *Django session cookies only*: simpler and secure for same-site browsers, but unsuitable for
  future non-browser clients.
- *Stateless JWT only (no server session)*: cannot revoke access tokens before expiry; fails the
  "immediate deactivation" requirement.
- *SimpleJWT blacklist app*: blacklists individual tokens but lacks family revocation and atomic
  compare-and-swap on rotation.
- *Redis-based rate limiting*: atomic and fast, but adds infrastructure not otherwise needed in
  Phase 1; the PostgreSQL limiter can be swapped later behind the same interface.

## Consequences

- One extra indexed query per authenticated request.
- Concurrent refreshes with the same token (two tabs) revoke the session; the frontend must
  single-flight refresh requests. This is the deliberate secure default.
- Limiter table needs periodic purging (management command).
