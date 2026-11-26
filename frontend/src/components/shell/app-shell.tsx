"use client";

import { type ReactNode } from "react";

import { SidebarProvider } from "@/components/ui/sidebar";
import { type BreadcrumbItem } from "@/lib/navigation/types";

import { AppHeader } from "./app-header";
import { AppSidebar, type AppSidebarProps } from "./app-sidebar";

interface AppShellProps extends AppSidebarProps {
  breadcrumbs: readonly BreadcrumbItem[];
  /** Initial sidebar state from the `aems_sidebar` preference cookie (server-read). */
  defaultSidebarOpen?: boolean;
  headerActions?: ReactNode;
  children: ReactNode;
}

/**
 * The authenticated application frame: collapsible sidebar (off-canvas sheet below `lg`), sticky
 * header with breadcrumbs, and the `#main` landmark. Purely presentational: it renders the user,
 * organizations and navigation it is given; FE-1B supplies them from the API.
 */
export function AppShell({
  breadcrumbs,
  defaultSidebarOpen = true,
  headerActions,
  children,
  ...sidebar
}: AppShellProps) {
  return (
    <SidebarProvider defaultOpen={defaultSidebarOpen}>
      <AppSidebar {...sidebar} />
      <div className="relative flex min-h-svh w-full min-w-0 flex-1 flex-col bg-background">
        <AppHeader user={sidebar.user} breadcrumbs={breadcrumbs} actions={headerActions} />
        <main id="main" tabIndex={-1} className="flex-1 px-4 py-6 outline-none sm:px-6 lg:px-8">
          <div className="mx-auto w-full max-w-screen-xl space-y-8">{children}</div>
        </main>
      </div>
    </SidebarProvider>
  );
}
