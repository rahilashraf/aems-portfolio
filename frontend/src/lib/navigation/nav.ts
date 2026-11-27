import { LayoutDashboard } from "lucide-react";

import { hasAll, type PermissionChecker } from "@/lib/permissions";

import { type NavGroup, type NavItem } from "./types";

/**
 * Organization navigation registry. Only features that exist are listed: FE-1 has the read-only
 * overview. Later batches add their own entries (with `requires`) when their pages ship, so the
 * sidebar never shows a non-functional destination.
 *
 * `basePath` is the organization root (`/o/{orgId}` from FE-1B; the dev preview passes its own).
 */
export function organizationNavigation(basePath: string): NavGroup[] {
  return [
    {
      id: "organization",
      label: "Organization",
      items: [{ id: "overview", label: "Overview", href: basePath, icon: LayoutDashboard }],
    },
  ];
}

/** Drop items the caller may not use, and groups left empty. Presentation only. */
export function filterNavigation(groups: readonly NavGroup[], can: PermissionChecker): NavGroup[] {
  return groups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => hasAll(can, item.requires)),
    }))
    .filter((group) => group.items.length > 0);
}

/** Whether `item` is the current page for `pathname` (exact, or nested when requested). */
export function isActive(item: NavItem, pathname: string): boolean {
  const normalize = (path: string) => (path.length > 1 ? path.replace(/\/+$/, "") : path);
  const current = normalize(pathname);
  const target = normalize(item.href);
  return current === target || (item.matchNested === true && current.startsWith(`${target}/`));
}
