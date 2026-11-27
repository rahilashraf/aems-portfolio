/** First focusable element on every page: jumps keyboard users past navigation to `#main`. */
export function SkipLink() {
  return (
    <a
      href="#main"
      className="sr-only z-50 rounded-md border bg-background px-3 py-2 text-sm font-medium text-foreground shadow-sm focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus-visible:ring-2 focus-visible:ring-ring"
    >
      Skip to main content
    </a>
  );
}
