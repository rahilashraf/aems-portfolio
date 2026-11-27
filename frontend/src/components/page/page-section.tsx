import { type ReactNode, useId } from "react";

import { cn } from "@/lib/utils";

interface PageSectionProps {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** A titled region of a page (labelled `section`, h2 heading). */
export function PageSection({
  title,
  description,
  actions,
  children,
  className,
}: PageSectionProps) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className={cn("space-y-4", className)}>
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div className="space-y-1">
          <h2 id={headingId} className="text-base font-semibold">
            {title}
          </h2>
          {description ? <p className="text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
