import { type BreadcrumbItem } from "./types";

/**
 * Normalize a breadcrumb trail: drop empty labels and remove the link from the last item, which
 * is the current page (rendered with aria-current="page").
 */
export function buildBreadcrumbs(trail: readonly BreadcrumbItem[]): BreadcrumbItem[] {
  const items = trail.filter((item) => item.label.trim().length > 0);
  return items.map((item, index) =>
    index === items.length - 1 ? { label: item.label } : { ...item },
  );
}

/** Document title for a page: "Page · Organization · AEMS" (empty parts omitted). */
export function documentTitle(...parts: readonly (string | undefined)[]): string {
  return [...parts.filter((part): part is string => Boolean(part?.trim())), "AEMS"].join(" · ");
}
