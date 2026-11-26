import { FileQuestion } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/feedback/empty-state";
import { Button } from "@/components/ui/button";

export const metadata = { title: "Page not found" };

export default function NotFound() {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="flex min-h-svh items-center justify-center px-4 outline-none"
    >
      <div className="w-full max-w-md">
        <h1 className="sr-only">Page not found</h1>
        <EmptyState
          icon={FileQuestion}
          title="Page not found"
          description="The page you requested does not exist or is not available to you."
          action={
            <Button asChild variant="outline">
              <Link href="/">Go to the start page</Link>
            </Button>
          }
        />
      </div>
    </main>
  );
}
