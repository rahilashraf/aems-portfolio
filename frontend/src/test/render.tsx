import { render, type RenderOptions } from "@testing-library/react";
import { ThemeProvider } from "next-themes";
import { type ReactElement, type ReactNode } from "react";

import { TooltipProvider } from "@/components/ui/tooltip";

function Providers({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="light" enableSystem disableTransitionOnChange>
      <TooltipProvider delayDuration={0}>{children}</TooltipProvider>
    </ThemeProvider>
  );
}

/** Render with the application providers (theme, tooltips). */
export function renderWithProviders(ui: ReactElement, options?: Omit<RenderOptions, "wrapper">) {
  return render(ui, { wrapper: Providers, ...options });
}
