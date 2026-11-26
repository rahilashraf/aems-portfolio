"use client";

import "@/styles/globals.css";

/** Last-resort boundary when the root layout itself fails. Self-contained markup, no providers. */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body>
        <main id="main" className="flex min-h-svh items-center justify-center px-4">
          <div role="alert" className="w-full max-w-md space-y-3 rounded-lg border p-6">
            <h1 className="text-xl font-semibold">AEMS is unavailable</h1>
            <p className="text-muted-foreground">
              An unexpected error occurred. Try again in a moment.
            </p>
            {error.digest ? (
              <p className="text-xs text-muted-foreground">
                Reference: <span className="font-mono">{error.digest}</span>
              </p>
            ) : null}
            <button
              type="button"
              onClick={reset}
              className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground"
            >
              Try again
            </button>
          </div>
        </main>
      </body>
    </html>
  );
}
