import { type LucideIcon } from "lucide-react";

import { type PermissionCode } from "@/lib/permissions";

/** One sidebar entry. Items whose `requires` are not all held are not rendered at all. */
export interface NavItem {
  readonly id: string;
  readonly label: string;
  readonly href: string;
  readonly icon: LucideIcon;
  readonly requires?: readonly PermissionCode[];
  /** Match nested paths as active (default: exact match only). */
  readonly matchNested?: boolean;
}

export interface NavGroup {
  readonly id: string;
  readonly label: string;
  readonly items: readonly NavItem[];
}

export interface BreadcrumbItem {
  readonly label: string;
  readonly href?: string;
}
