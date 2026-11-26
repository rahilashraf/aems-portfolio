"use client";

import { type ReactNode } from "react";

import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { type BreadcrumbItem } from "@/lib/navigation/types";
import { type ShellUser } from "@/lib/shell/types";

import { AccountMenu } from "./account-menu";
import { Breadcrumbs } from "./breadcrumbs";

interface AppHeaderProps {
  user: ShellUser;
  breadcrumbs: readonly BreadcrumbItem[];
  /** Global, working actions only. */
  actions?: ReactNode;
}

export function AppHeader({ user, breadcrumbs, actions }: AppHeaderProps) {
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-6">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
      <Breadcrumbs items={breadcrumbs} />
      <div className="ml-auto flex items-center gap-2">
        {actions}
        <div className="lg:hidden">
          <AccountMenu user={user} variant="header" />
        </div>
      </div>
    </header>
  );
}
