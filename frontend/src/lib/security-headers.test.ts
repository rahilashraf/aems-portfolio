import { describe, expect, it } from "vitest";

import { HSTS_HEADER, SECURITY_HEADERS } from "./security-headers";

describe("baseline security headers", () => {
  const headers = Object.fromEntries(SECURITY_HEADERS.map(({ key, value }) => [key, value]));

  it("deny framing, sniffing and cross-origin opener access", () => {
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(headers["Permissions-Policy"]).toContain("camera=()");
  });

  it("uses a two-year HSTS policy in production", () => {
    expect(HSTS_HEADER).toEqual({
      key: "Strict-Transport-Security",
      value: "max-age=63072000; includeSubDomains",
    });
  });
});
