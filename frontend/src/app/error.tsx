"use client";

import { ErrorState } from "@/components/feedback/error-state";

/** Route-level error boundary. Shows a safe message and the error digest as a reference only. */
export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="flex min-h-svh items-center justify-center px-4 outline-none"
    >
      <div className="w-full max-w-md space-y-4">
        <h1 className="text-xl font-semibold">Something went wrong</h1>
        <ErrorState
          title="This page could not be displayed"
          description="An unexpected error occurred. Try again, or come back later."
          requestId={error.digest ?? null}
          onRetry={reset}
        />
      </div>
    </main>
  );
}
