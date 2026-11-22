# ADR-0012: API access-control enforcement and the public-endpoint allowlist

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Batch 2 introduced deny-by-default API permissions and an allowlist of public endpoints, checked
statically by inspecting each view's `permission_classes`. Review AEMS-007 found that static
inspection alone can be bypassed by:
- an empty `permission_classes` list (DRF then allows everyone);
- overriding `get_permissions()`;
- ViewSet action-specific permissions;
- custom permission classes whose `has_permission` returns True;
- duplicate URL names;
- using `PublicEndpoint` on a route that is not allowlisted.

## Decision

Enforcement is layered and fails closed:

1. **Deny by default:** `DEFAULT_PERMISSION_CLASSES = [DenyAll]`.
2. **`PublicEndpoint` checks the allowlist at runtime.** It grants access only if:
   - the resolved URL name is in `API_PUBLIC_ENDPOINTS`;
   - that name maps to exactly one route in the active URLconf;
   - the request was resolved to that route.

   A duplicated name therefore denies access on *all* of its routes.
3. **Runtime guard on every DRF view** (`PublicAccessGuard`, built into `AemsAPIView`,
   `AemsGenericAPIView`, `AemsViewSet` and `AemsGenericViewSet`).
   - After DRF's own permission checks pass, it refuses any **unauthenticated** request unless
     the endpoint passes the same allowlist test.
   - It does not care how the permissions were produced (class attributes, `get_permissions()`,
     action overrides or custom classes).
   - Blocked attempts are logged as `security.public_access_blocked`.
4. **Static system checks.** They run with every `manage.py` command and in CI (`make check`):
   - `core.E001`: `PublicEndpoint` used on an unlisted or unnamed route.
   - `core.E002`: `AllowAny`, or a subclass other than `PublicEndpoint`.
   - `core.E003`: empty `permission_classes`, including on ViewSet actions.
   - `core.E004`: a DRF view without `PublicAccessGuard`.
   - `core.E005`: a URL name used by a DRF view is registered more than once.

Dynamic permissions cannot be proven statically. `core.E004` guarantees they are covered at runtime.

## Transition to Batch 3 (authentication)

- Authentication classes are added. `DEFAULT_PERMISSION_CLASSES` becomes authenticated access, and
  `DenyAll` stays available for explicit lockdown.
- The guard continues to apply only to **unauthenticated** requests. Authenticated requests are
  governed by their permission classes, and from Batch 6 by organization RBAC.
- Unauthenticated requests to non-allowlisted endpoints will then receive `401` with
  `WWW-Authenticate`, because DRF raises `NotAuthenticated` when authenticators exist, instead of
  `403`.
- Login, token refresh, password reset and invitation preview/accept become new allowlisted
  public endpoints. Each needs a reviewed entry in `API_PUBLIC_ENDPOINTS`.

## Consequences

- Making an endpoint public requires two deliberate, reviewable changes: the permission class and
  an allowlist entry.
- Test-only public fixtures are allowlisted only in `config.settings.test`. A test asserts that
  list matches the fixture URLconf exactly.
- Every DRF view must use the project base classes or the guard mixin.
