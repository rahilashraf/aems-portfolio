import { LayoutDashboard, Users } from "lucide-react";
import { describe, expect, it } from "vitest";

import { createPermissionChecker } from "@/lib/permissions";

import { filterNavigation, isActive, organizationNavigation } from "./nav";
import { type NavGroup } from "./types";

const GROUPS: NavGroup[] = [
  {
    id: "main",
    label: "Main",
    items: [
      { id: "overview", label: "Overview", href: "/o/1", icon: LayoutDashboard },
      {
        id: "people",
        label: "People",
        href: "/o/1/people",
        icon: Users,
        requires: ["members.view"],
        matchNested: true,
      },
    ],
  },
  {
    id: "admin",
    label: "Administration",
    items: [
      {
        id: "roles",
        label: "Roles",
        href: "/o/1/roles",
        icon: Users,
        requires: ["roles.view", "roles.manage"],
      },
    ],
  },
];

describe("organizationNavigation", () => {
  it("lists only shipped destinations, rooted at the organization path", () => {
    const groups = organizationNavigation("/o/abc");
    expect(groups.flatMap((group) => group.items.map((item) => [item.id, item.href]))).toEqual([
      ["overview", "/o/abc"],
    ]);
  });
});

describe("filterNavigation", () => {
  it("keeps unrestricted items and items whose permissions are all held", () => {
    const result = filterNavigation(GROUPS, createPermissionChecker(["members.view"]));
    expect(result.map((group) => group.id)).toEqual(["main"]);
    expect(result[0]!.items.map((item) => item.id)).toEqual(["overview", "people"]);
  });

  it("drops partially satisfied items and empty groups", () => {
    const result = filterNavigation(GROUPS, createPermissionChecker(["roles.view"]));
    expect(result.flatMap((group) => group.items.map((item) => item.id))).toEqual(["overview"]);
  });

  it("does not mutate the registry", () => {
    filterNavigation(GROUPS, createPermissionChecker([]));
    expect(GROUPS[0]!.items).toHaveLength(2);
  });
});

describe("isActive", () => {
  const overview = GROUPS[0]!.items[0]!;
  const people = GROUPS[0]!.items[1]!;

  it("matches exactly, ignoring trailing slashes", () => {
    expect(isActive(overview, "/o/1")).toBe(true);
    expect(isActive(overview, "/o/1/")).toBe(true);
    expect(isActive(overview, "/o/1/people")).toBe(false);
  });

  it("matches nested paths only when requested", () => {
    expect(isActive(people, "/o/1/people/42")).toBe(true);
    expect(isActive(people, "/o/1/peoplex")).toBe(false);
  });

  it("handles the root path", () => {
    expect(isActive({ ...overview, href: "/" }, "/")).toBe(true);
  });
});
