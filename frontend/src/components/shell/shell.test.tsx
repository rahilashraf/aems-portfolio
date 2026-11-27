import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { filterNavigation, organizationNavigation } from "@/lib/navigation/nav";
import { createPermissionChecker, type PermissionCode } from "@/lib/permissions";
import { SIDEBAR_COOKIE_NAME } from "@/lib/shell/sidebar-state";
import { type ShellOrganization } from "@/lib/shell/types";
import { axeViolations } from "@/test/axe";
import { renderWithProviders } from "@/test/render";

import { AppShell } from "./app-shell";
import { Breadcrumbs } from "./breadcrumbs";

const navigation = { pathname: "/o/org-1" };
vi.mock("next/navigation", () => ({ usePathname: () => navigation.pathname }));

const USER = { fullName: "Ada Lovelace", email: "ada@example.org" };
const ORGS: ShellOrganization[] = [
  { id: "org-1", name: "Northwind Academy", type: "school" },
  { id: "org-2", name: "Lakeside University", type: "university" },
];

function setViewport(width: number) {
  (globalThis as unknown as { setViewportWidth: (w: number) => void }).setViewportWidth(width);
}

function Harness({
  granted = [],
  defaultOpen = true,
}: {
  granted?: PermissionCode[];
  defaultOpen?: boolean;
}) {
  const [current, setCurrent] = useState("org-1");
  const organization = ORGS.find((org) => org.id === current)!;
  const nav = filterNavigation(
    organizationNavigation(`/o/${current}`),
    createPermissionChecker(granted),
  );
  return (
    <AppShell
      user={USER}
      organization={organization}
      organizations={ORGS}
      navigation={nav}
      onSelectOrganization={setCurrent}
      allOrganizationsHref="/organizations"
      breadcrumbs={[{ label: organization.name, href: `/o/${current}` }, { label: "Overview" }]}
      defaultSidebarOpen={defaultOpen}
    >
      <h1>Overview</h1>
    </AppShell>
  );
}

beforeEach(() => {
  setViewport(1280);
  navigation.pathname = "/o/org-1";
});

describe("AppShell (desktop)", () => {
  it("renders landmarks, the current organization, navigation and breadcrumbs", async () => {
    const { container } = renderWithProviders(<Harness />);
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveAttribute("id", "main");
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    const overview = within(nav).getByRole("link", { name: "Overview" });
    expect(overview).toHaveAttribute("href", "/o/org-1");
    expect(overview).toHaveAttribute("aria-current", "page");
    expect(
      screen.getByRole("button", { name: /^Northwind Academy School Switch organization$/ }),
    ).toBeInTheDocument();
    const crumbs = screen.getByRole("navigation", { name: "breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "Northwind Academy" })).toHaveAttribute(
      "href",
      "/o/org-1",
    );
    expect(within(crumbs).getByText("Overview")).toHaveAttribute("aria-current", "page");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("marks no item current on other paths", () => {
    navigation.pathname = "/o/org-1/elsewhere";
    renderWithProviders(<Harness />);
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(nav).getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });

  it("switches organization with the keyboard", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Harness />);
    const trigger = screen.getByRole("button", {
      name: /^Northwind Academy School Switch organization$/,
    });
    trigger.focus();
    await user.keyboard("{Enter}");
    const menu = await screen.findByRole("menu");
    expect(within(menu).getByRole("menuitem", { name: /Northwind Academy/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
    expect(within(menu).getByRole("menuitem", { name: "All organizations" })).toHaveAttribute(
      "href",
      "/organizations",
    );
    await user.click(within(menu).getByRole("menuitem", { name: /Lakeside University/ }));
    await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
    expect(
      screen.getByRole("button", {
        name: /^Lakeside University University Switch organization$/,
      }),
    ).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("href", "/o/org-2");
  });

  it("re-selecting the current organization changes nothing", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Harness />);
    await user.click(
      screen.getByRole("button", { name: /^Northwind Academy School Switch organization$/ }),
    );
    await user.click(
      within(await screen.findByRole("menu")).getByRole("menuitem", {
        name: /Northwind Academy/,
      }),
    );
    expect(
      screen.getByRole("button", { name: /^Northwind Academy School Switch organization$/ }),
    ).toBeInTheDocument();
  });

  it("offers identity and a working theme choice in the account menu", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: /Ada Lovelace.*Account menu/ }));
    const menu = await screen.findByRole("menu");
    expect(menu).toHaveTextContent("Ada Lovelace");
    expect(menu).toHaveTextContent("ada@example.org");
    expect(
      within(menu)
        .getAllByRole("menuitemradio")
        .map((item) => item.textContent),
    ).toEqual(["Light", "Dark", "System"]);
    expect(within(menu).queryByRole("menuitem", { name: /sign out/i })).toBeNull();
    await user.click(within(menu).getByRole("menuitemradio", { name: "Dark" }));
    await waitFor(() => expect(document.documentElement).toHaveClass("dark"));
    expect(window.localStorage.getItem("theme")).toBe("dark");
  });

  it("collapses with Ctrl+B and remembers the preference in a cookie", async () => {
    const user = userEvent.setup();
    const { container } = renderWithProviders(<Harness />);
    const sidebar = () => container.querySelector('[data-slot="sidebar"][data-state]');
    expect(sidebar()).toHaveAttribute("data-state", "expanded");
    await user.keyboard("{Control>}b{/Control}");
    expect(sidebar()).toHaveAttribute("data-state", "collapsed");
    expect(document.cookie).toContain(`${SIDEBAR_COOKIE_NAME}=false`);
    await user.click(screen.getByRole("button", { name: "Toggle navigation" }));
    expect(sidebar()).toHaveAttribute("data-state", "expanded");
    expect(document.cookie).toContain(`${SIDEBAR_COOKIE_NAME}=true`);
  });

  it("starts collapsed when the preference says so", () => {
    const { container } = renderWithProviders(<Harness defaultOpen={false} />);
    expect(container.querySelector('[data-slot="sidebar"][data-state]')).toHaveAttribute(
      "data-state",
      "collapsed",
    );
  });
});

describe("AppShell (mobile)", () => {
  it("opens navigation as a modal sheet that closes on navigation", async () => {
    setViewport(390);
    const user = userEvent.setup();
    renderWithProviders(<Harness />);
    expect(screen.queryByRole("navigation", { name: "Main navigation" })).toBeNull();
    // The header carries the account menu below `lg`.
    expect(screen.getByRole("banner")).toContainElement(
      screen.getByRole("button", { name: "Account menu" }),
    );

    const trigger = screen.getByRole("button", { name: "Toggle navigation" });
    await user.click(trigger);
    const sheet = await screen.findByRole("dialog", { name: "Navigation" });
    const link = within(sheet).getByRole("link", { name: "Overview" });
    await act(async () => {
      link.addEventListener("click", (event) => event.preventDefault(), { once: true });
      await user.click(link);
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("closes with Escape and returns focus to the trigger", async () => {
    setViewport(390);
    const user = userEvent.setup();
    renderWithProviders(<Harness />);
    const trigger = screen.getByRole("button", { name: "Toggle navigation" });
    await user.click(trigger);
    const sheet = await screen.findByRole("dialog", { name: "Navigation" });
    await waitFor(() => expect(sheet).toContainElement(document.activeElement as HTMLElement));
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(trigger).toHaveFocus();
  });
});

describe("Breadcrumbs", () => {
  it("renders nothing for an empty trail", () => {
    const { container } = render(<Breadcrumbs items={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders unlinked items as plain text and only the last as the current page", () => {
    render(<Breadcrumbs items={[{ label: "Settings" }, { label: "Profile" }]} />);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    expect(screen.getByText("Settings")).not.toHaveAttribute("aria-current");
    expect(screen.getByText("Profile")).toHaveAttribute("aria-current", "page");
  });
});
