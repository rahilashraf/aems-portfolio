import { describe, expect, it } from "vitest";

import { initials, organizationTypeLabel } from "./format";
import { sidebarDefaultOpen } from "./sidebar-state";
import { ORGANIZATION_TYPES } from "./types";

describe("initials", () => {
  it.each([
    ["Northwind Academy", "NA"],
    ["Lakeside University of Arts", "LA"],
    ["  single  ", "S"],
    ["élise o'neil", "ÉO"],
    ["Harbor-Training Institute", "HI"],
  ])("%j → %s", (name, expected) => {
    expect(initials(name)).toBe(expected);
  });

  it("falls back to the first letter of the fallback, then '?'", () => {
    expect(initials("", "preview@example.org")).toBe("P");
    expect(initials("!!!", "")).toBe("?");
  });
});

describe("organizationTypeLabel", () => {
  it("labels every backend organization type", () => {
    expect(ORGANIZATION_TYPES.map(organizationTypeLabel)).toEqual([
      "School",
      "University",
      "Training provider",
      "Organization",
    ]);
  });
});

describe("sidebarDefaultOpen", () => {
  it("is expanded unless the preference is explicitly 'false'", () => {
    expect(sidebarDefaultOpen(undefined)).toBe(true);
    expect(sidebarDefaultOpen("true")).toBe(true);
    expect(sidebarDefaultOpen("garbage")).toBe(true);
    expect(sidebarDefaultOpen("false")).toBe(false);
  });
});
