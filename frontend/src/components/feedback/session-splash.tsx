import { AemsMark } from "@/components/brand/aems-mark";
import { Spinner } from "@/components/ui/spinner";

/** Full-screen state while the session is being established (used from FE-1B). */
export function SessionSplash({ label = "Loading AEMS" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-svh flex-col items-center justify-center gap-4 bg-background"
    >
      <AemsMark className="size-10" />
      <Spinner className="size-5 text-muted-foreground" aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </div>
  );
}
