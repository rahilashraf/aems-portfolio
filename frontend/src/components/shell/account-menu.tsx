"use client";

import { ChevronsUpDown, CircleUserRound } from "lucide-react";
import { type ReactNode } from "react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { initials } from "@/lib/shell/format";
import { type ShellUser } from "@/lib/shell/types";

import { ThemeMenuItems } from "./theme-menu";
import { useRailTooltip } from "./use-rail-tooltip";

/**
 * Account controls: identity and theme. Sign-out and password management arrive with the
 * authentication batch (FE-2); no inactive entries are shown before then.
 */
export function AccountMenu({ user, variant }: { user: ShellUser; variant: "sidebar" | "header" }) {
  const label = initials(user.fullName, user.email);
  const content = (
    <DropdownMenuContent
      align="end"
      side={variant === "sidebar" ? "top" : "bottom"}
      className="w-64"
    >
      <DropdownMenuLabel className="font-normal">
        <span className="block truncate font-medium">{user.fullName}</span>
        <span className="block truncate text-xs text-muted-foreground">{user.email}</span>
      </DropdownMenuLabel>
      <DropdownMenuSeparator />
      <ThemeMenuItems />
    </DropdownMenuContent>
  );

  if (variant === "header") {
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          {/* Icon only: visible initials would not match the accessible name (WCAG 2.5.3). */}
          <Button variant="ghost" size="icon" className="rounded-full" aria-label="Account menu">
            <CircleUserRound className="size-5" aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        {content}
      </DropdownMenu>
    );
  }

  return <SidebarAccountMenu user={user} label={label} content={content} />;
}

function SidebarAccountMenu({
  user,
  label,
  content,
}: {
  user: ShellUser;
  label: string;
  content: ReactNode;
}) {
  const tooltip = useRailTooltip(user.fullName);
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" {...(tooltip ? { tooltip } : {})}>
              <Avatar className="size-8 rounded-md" aria-hidden="true">
                <AvatarFallback className="rounded-md text-xs font-medium">{label}</AvatarFallback>
              </Avatar>
              <span className="grid min-w-0 flex-1 text-left leading-tight">
                <span className="truncate font-medium">{user.fullName}</span>{" "}
                <span className="truncate text-xs text-muted-foreground">{user.email}</span>
              </span>{" "}
              <span className="sr-only">Account menu</span>
              <ChevronsUpDown className="ml-auto size-4" aria-hidden="true" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          {content}
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
