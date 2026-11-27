"use client";

import { AlertTriangle, RotateCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  title?: string;
  description?: string;
  /** Server correlation id (`request_id` / `X-Request-ID`), shown so support can trace it. */
  requestId?: string | null;
  onRetry?: () => void;
  className?: string;
}

/** A failed load or action. Never shows server internals; only a safe message and the request id. */
export function ErrorState({
  title = "Something went wrong",
  description = "The request could not be completed. Try again in a moment.",
  requestId,
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4",
        className,
      )}
    >
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden="true" />
        <div className="space-y-1">
          <p className="font-medium">{title}</p>
          <p className="text-muted-foreground">{description}</p>
          {requestId ? (
            <p className="text-xs text-muted-foreground">
              Reference: <span className="font-mono">{requestId}</span>
            </p>
          ) : null}
        </div>
      </div>
      {onRetry ? (
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          <RotateCw aria-hidden="true" />
          Try again
        </Button>
      ) : null}
    </div>
  );
}
