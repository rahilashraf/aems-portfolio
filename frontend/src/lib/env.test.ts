import { describe, expect, it } from "vitest";

import { devRoutesEnabled, parseServerEnv } from "./env";

describe("parseServerEnv", () => {
  it("defaults to development with review routes disabled", () => {
    expect(parseServerEnv({})).toEqual({
      NODE_ENV: "development",
      AEMS_ENABLE_DEV_ROUTES: false,
    });
  });

  it.each([
    ["true", true],
    ["false", false],
  ])("accepts AEMS_ENABLE_DEV_ROUTES=%s", (value, expected) => {
    expect(parseServerEnv({ AEMS_ENABLE_DEV_ROUTES: value }).AEMS_ENABLE_DEV_ROUTES).toBe(expected);
  });

  it.each(["1", "yes", "TRUE", ""])("rejects AEMS_ENABLE_DEV_ROUTES=%j", (value) => {
    expect(() => parseServerEnv({ AEMS_ENABLE_DEV_ROUTES: value })).toThrow(
      /AEMS_ENABLE_DEV_ROUTES/,
    );
  });

  it("refuses review routes in a Vercel production deployment", () => {
    expect(() =>
      parseServerEnv({ AEMS_ENABLE_DEV_ROUTES: "true", VERCEL_ENV: "production" }),
    ).toThrow(/must not be enabled in a production deployment/);
    expect(
      parseServerEnv({ AEMS_ENABLE_DEV_ROUTES: "true", VERCEL_ENV: "preview" })
        .AEMS_ENABLE_DEV_ROUTES,
    ).toBe(true);
  });

  it("rejects unknown NODE_ENV values and lists every problem", () => {
    expect(() => parseServerEnv({ NODE_ENV: "staging", AEMS_ENABLE_DEV_ROUTES: "maybe" })).toThrow(
      /NODE_ENV[\s\S]*AEMS_ENABLE_DEV_ROUTES|AEMS_ENABLE_DEV_ROUTES[\s\S]*NODE_ENV/,
    );
  });
});

describe("devRoutesEnabled", () => {
  it("is true only for the inlined build flag 'true'", () => {
    expect(devRoutesEnabled("true")).toBe(true);
    expect(devRoutesEnabled("false")).toBe(false);
    expect(devRoutesEnabled(undefined)).toBe(false);
    expect(devRoutesEnabled("TRUE")).toBe(false);
  });
});
