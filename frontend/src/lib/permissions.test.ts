import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { PERMISSION_CODES, createPermissionChecker, hasAll, isPermissionCode } from "./permissions";

describe("permission helpers", () => {
  it("recognizes catalog codes only", () => {
    expect(isPermissionCode("members.view")).toBe(true);
    expect(isPermissionCode("members.delete")).toBe(false);
  });

  it("grants exactly the held codes and ignores unknown ones", () => {
    const can = createPermissionChecker(["members.view", "not.a.code", "audit.view"]);
    expect(can("members.view")).toBe(true);
    expect(can("audit.view")).toBe(true);
    expect(can("members.manage")).toBe(false);
  });

  it("requires every code; an empty requirement is satisfied", () => {
    const can = createPermissionChecker(["roles.view"]);
    expect(hasAll(can)).toBe(true);
    expect(hasAll(can, [])).toBe(true);
    expect(hasAll(can, ["roles.view"])).toBe(true);
    expect(hasAll(can, ["roles.view", "roles.manage"])).toBe(false);
  });
});

describe("catalog drift", () => {
  it("matches the backend permission catalog (backend/apps/rbac/catalog.py)", () => {
    const catalog = readFileSync(
      path.resolve(__dirname, "../../../backend/apps/rbac/catalog.py"),
      "utf8",
    );
    // Definitions are tuples: ("code", "description", "category").
    const codes = [...catalog.matchAll(/\(\s*"([a-z]+\.[a-z_]+)",\s*"/g)].map((match) => match[1]);
    expect(new Set(codes)).toEqual(new Set(PERMISSION_CODES));
  });
});
