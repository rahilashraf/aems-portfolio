/**
 * Organization permission codes (the backend catalog, ADR-0017). Kept in sync with
 * `backend/apps/rbac/catalog.py` by `permissions.test.ts`.
 *
 * The frontend uses permissions for presentation only (what to show); the API enforces them.
 */
export const PERMISSION_CODES = [
  "organization.view",
  "organization.update",
  "members.view",
  "members.manage",
  "invitations.manage",
  "roles.view",
  "roles.manage",
  "audit.view",
] as const;

export type PermissionCode = (typeof PERMISSION_CODES)[number];

export type PermissionChecker = (code: PermissionCode) => boolean;

const KNOWN = new Set<string>(PERMISSION_CODES);

export function isPermissionCode(value: string): value is PermissionCode {
  return KNOWN.has(value);
}

/** A checker over the granted codes. Unknown codes are ignored (they grant nothing). */
export function createPermissionChecker(granted: Iterable<string>): PermissionChecker {
  const held = new Set<PermissionCode>();
  for (const code of granted) {
    if (isPermissionCode(code)) held.add(code);
  }
  return (code) => held.has(code);
}

/** True when every required code is held; an empty requirement is always satisfied. */
export function hasAll(can: PermissionChecker, required: readonly PermissionCode[] = []): boolean {
  return required.every((code) => can(code));
}
