import { ShieldOff } from "lucide-react";

import { EmptyState } from "./empty-state";

/** Shown when the caller is signed in but lacks the permission for a section or page. */
export function PermissionDenied({
  title = "You don't have access to this",
  description = "Ask an administrator of this organization if you need access.",
  className,
}: {
  title?: string;
  description?: string;
  className?: string;
}) {
  return (
    <EmptyState icon={ShieldOff} title={title} description={description} className={className} />
  );
}
