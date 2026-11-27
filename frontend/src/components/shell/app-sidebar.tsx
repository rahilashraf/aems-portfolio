"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from "@/components/ui/sidebar";
import { isActive } from "@/lib/navigation/nav";
import { type NavGroup, type NavItem } from "@/lib/navigation/types";
import { type ShellOrganization, type ShellUser } from "@/lib/shell/types";

import { AccountMenu } from "./account-menu";
import { OrgSwitcher } from "./org-switcher";
import { useRailTooltip } from "./use-rail-tooltip";

export interface AppSidebarProps {
  user: ShellUser;
  organization: ShellOrganization;
  organizations: readonly ShellOrganization[];
  /** Already filtered for the caller's permissions (see `filterNavigation`). */
  navigation: readonly NavGroup[];
  onSelectOrganization: (organizationId: string) => void;
  allOrganizationsHref?: string;
}

export function AppSidebar({
  user,
  organization,
  organizations,
  navigation,
  onSelectOrganization,
  allOrganizationsHref,
}: AppSidebarProps) {
  const pathname = usePathname();
  const { isMobile, setOpenMobile } = useSidebar();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <OrgSwitcher
          current={organization}
          organizations={organizations}
          onSelect={onSelectOrganization}
          {...(allOrganizationsHref ? { allOrganizationsHref } : {})}
        />
      </SidebarHeader>
      <SidebarContent>
        <nav aria-label="Main navigation">
          {navigation.map((group) => (
            <SidebarGroup key={group.id}>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarMenu>
                {group.items.map((item) => (
                  <NavLink
                    key={item.id}
                    item={item}
                    active={isActive(item, pathname)}
                    onNavigate={() => {
                      if (isMobile) setOpenMobile(false);
                    }}
                  />
                ))}
              </SidebarMenu>
            </SidebarGroup>
          ))}
        </nav>
      </SidebarContent>
      <SidebarFooter>
        <AccountMenu user={user} variant="sidebar" />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

function NavLink({
  item,
  active,
  onNavigate,
}: {
  item: NavItem;
  active: boolean;
  onNavigate: () => void;
}) {
  const tooltip = useRailTooltip(item.label);
  const Icon = item.icon;
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={active} {...(tooltip ? { tooltip } : {})}>
        <Link href={item.href} aria-current={active ? "page" : undefined} onClick={onNavigate}>
          <Icon aria-hidden="true" />
          <span>{item.label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
