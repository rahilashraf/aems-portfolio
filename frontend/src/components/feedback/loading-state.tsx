"use client";

import { Skeleton } from "@/components/ui/skeleton";
import { useDelayedVisibility } from "@/hooks/use-delayed-visibility";
import { cn } from "@/lib/utils";

type LoadingVariant = "page" | "card" | "table";

interface LoadingStateProps {
  /** Announced to assistive technology, e.g. "Loading organization". */
  label: string;
  variant?: LoadingVariant;
  /** Rows for the table variant. */
  rows?: number;
  className?: string;
  /** Delay before the skeleton appears (ms). */
  delayMs?: number;
}

/**
 * Skeleton placeholder that mirrors the final layout (no layout shift). It appears only after a
 * short delay so fast responses never flash, and is announced politely to screen readers.
 */
export function LoadingState({
  label,
  variant = "card",
  rows = 5,
  className,
  delayMs,
}: LoadingStateProps) {
  const visible = useDelayedVisibility(true, delayMs);
  return (
    <div role="status" aria-live="polite" aria-busy="true" className={cn("w-full", className)}>
      <span className="sr-only">{label}</span>
      {visible ? <Skeletons variant={variant} rows={rows} /> : null}
    </div>
  );
}

function Skeletons({ variant, rows }: { variant: LoadingVariant; rows: number }) {
  if (variant === "page") {
    return (
      <div className="space-y-6" aria-hidden="true" data-testid="loading-skeleton">
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-4 w-80 max-w-full" />
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Skeleton className="h-36" />
          <Skeleton className="h-36" />
        </div>
      </div>
    );
  }
  if (variant === "table") {
    return (
      <div className="space-y-2" aria-hidden="true" data-testid="loading-skeleton">
        <Skeleton className="h-9 w-full" />
        {Array.from({ length: rows }, (_, index) => (
          <Skeleton key={index} className="h-10 w-full" />
        ))}
      </div>
    );
  }
  return (
    <div className="space-y-3" aria-hidden="true" data-testid="loading-skeleton">
      <Skeleton className="h-5 w-40" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-2/3" />
    </div>
  );
}
