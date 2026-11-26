import { notFound } from "next/navigation";
import { type ReactNode } from "react";

import { devRoutesEnabled } from "@/lib/env";

export const metadata = { robots: { index: false, follow: false } };

/**
 * Development-only review routes (component gallery and shell preview). They exist only when the
 * build sets AEMS_ENABLE_DEV_ROUTES=true; every other build answers 404 (tested).
 */
export default function DevLayout({ children }: { children: ReactNode }) {
  if (!devRoutesEnabled()) notFound();
  return children;
}
