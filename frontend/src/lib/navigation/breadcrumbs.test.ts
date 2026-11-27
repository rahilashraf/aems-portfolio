import { describe, expect, it } from "vitest";

import { buildBreadcrumbs, documentTitle } from "./breadcrumbs";

describe("buildBreadcrumbs", () => {
  it("removes the link from the current (last) page and drops empty labels", () => {
    expect(
      buildBreadcrumbs([
        { label: "Organizations", href: "/organizations" },
        { label: " ", href: "/ignored" },
        { label: "Acme", href: "/o/1" },
        { label: "Overview", href: "/o/1" },
      ]),
    ).toEqual([
      { label: "Organizations", href: "/organizations" },
      { label: "Acme", href: "/o/1" },
      { label: "Overview" },
    ]);
  });

  it("returns an empty trail unchanged", () => {
    expect(buildBreadcrumbs([])).toEqual([]);
  });
});

describe("documentTitle", () => {
  it("joins the non-empty parts and appends the product name", () => {
    expect(documentTitle("Overview", "Acme")).toBe("Overview · Acme · AEMS");
    expect(documentTitle(undefined, " ", "Overview")).toBe("Overview · AEMS");
    expect(documentTitle()).toBe("AEMS");
  });
});
