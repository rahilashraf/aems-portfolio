import { AemsMark } from "@/components/brand/aems-mark";

/**
 * FE-1A production surface: a neutral holding page with no controls. FE-1B replaces it with the
 * session-aware entry point once the application is connected to the AEMS API.
 */
export default function HoldingPage() {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="flex min-h-svh items-center justify-center px-4 py-16 outline-none"
    >
      <div className="w-full max-w-md space-y-6 text-center">
        <AemsMark className="mx-auto size-12" />
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold">AEMS</h1>
          <p className="text-muted-foreground">Assessment &amp; Examination Management System</p>
        </div>
        <p className="rounded-lg border bg-card px-4 py-3 text-card-foreground shadow-xs">
          This web application is not yet connected to the AEMS service.
        </p>
        <p className="text-xs text-muted-foreground">© 2026 Rahil Ashraf. All rights reserved.</p>
      </div>
    </main>
  );
}
