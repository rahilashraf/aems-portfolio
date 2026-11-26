"use client";

import { Check, ChevronsUpDown } from "lucide-react";
import Link from "next/link";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { initials, organizationTypeLabel } from "@/lib/shell/format";
import { type ShellOrganization } from "@/lib/shell/types";
import { cn } from "@/lib/utils";

import { useRailTooltip } from "./use-rail-tooltip";

interface OrgSwitcherProps {
  current: ShellOrganization;
  organizations: readonly ShellOrganization[];
  onSelect: (organizationId: string) => void;
  /** Link to the full organization list, shown when not every organization is listed here. */
  allOrganizationsHref?: string;
}

/** Current organization identity, and switching between the caller's organizations. */
export function OrgSwitcher({
  current,
  organizations,
  onSelect,
  allOrganizationsHref,
}: OrgSwitcherProps) {
  const tooltip = useRailTooltip(current.name);
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" {...(tooltip ? { tooltip } : {})}>
              <OrgAvatar organization={current} />
              <span className="grid min-w-0 flex-1 text-left leading-tight">
                <span className="truncate font-semibold">{current.name}</span>{" "}
                <span className="truncate text-xs text-muted-foreground">
                  {organizationTypeLabel(current.type)}
                </span>
              </span>{" "}
              <span className="sr-only">Switch organization</span>
              <ChevronsUpDown className="ml-auto size-4" aria-hidden="true" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="start"
            side="bottom"
            className="w-(--radix-dropdown-menu-trigger-width) min-w-60"
          >
            <DropdownMenuLabel className="text-xs font-medium text-muted-foreground">
              Organizations
            </DropdownMenuLabel>
            {organizations.map((organization) => {
              const selected = organization.id === current.id;
              return (
                <DropdownMenuItem
                  key={organization.id}
                  onSelect={() => {
                    if (!selected) onSelect(organization.id);
                  }}
                  aria-current={selected ? "true" : undefined}
                  className="gap-2"
                >
                  <OrgAvatar organization={organization} className="size-6 text-[0.625rem]" />
                  <span className="min-w-0 flex-1 truncate">{organization.name}</span>
                  <Check
                    className={cn("size-4", selected ? "opacity-100" : "opacity-0")}
                    aria-hidden="true"
                  />
                </DropdownMenuItem>
              );
            })}
            {allOrganizationsHref ? (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link href={allOrganizationsHref}>All organizations</Link>
                </DropdownMenuItem>
              </>
            ) : null}
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}

function OrgAvatar({
  organization,
  className,
}: {
  organization: ShellOrganization;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-8 shrink-0 items-center justify-center rounded-md bg-sidebar-primary text-xs font-semibold text-sidebar-primary-foreground",
        className,
      )}
    >
      {initials(organization.name)}
    </span>
  );
}
