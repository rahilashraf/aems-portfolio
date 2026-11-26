import Link from "next/link";
import { Fragment } from "react";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { buildBreadcrumbs } from "@/lib/navigation/breadcrumbs";
import { type BreadcrumbItem as Crumb } from "@/lib/navigation/types";

/** Breadcrumb trail; the last item is the current page. Below `md` only the current page shows. */
export function Breadcrumbs({ items }: { items: readonly Crumb[] }) {
  const trail = buildBreadcrumbs(items);
  if (trail.length === 0) return null;
  return (
    <Breadcrumb className="min-w-0">
      <BreadcrumbList className="flex-nowrap">
        {trail.map((item, index) => {
          const last = index === trail.length - 1;
          return (
            <Fragment key={`${item.label}-${index}`}>
              <BreadcrumbItem className={last ? "min-w-0" : "hidden md:inline-flex"}>
                {last ? (
                  // Plain text with aria-current: the upstream role="link" aria-disabled span
                  // would be announced as a disabled link.
                  <BreadcrumbPage role={undefined} aria-disabled={undefined} className="truncate">
                    {item.label}
                  </BreadcrumbPage>
                ) : !item.href ? (
                  <span>{item.label}</span>
                ) : (
                  <BreadcrumbLink asChild>
                    <Link href={item.href}>{item.label}</Link>
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
              {last ? null : <BreadcrumbSeparator className="hidden md:block" />}
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
