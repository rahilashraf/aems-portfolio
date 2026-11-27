import { type NextConfig } from "next";

import { parseServerEnv } from "./src/lib/env";
import { HSTS_HEADER, SECURITY_HEADERS } from "./src/lib/security-headers";

// Fail fast: an invalid environment stops `next dev`, `next build` and `next start`.
const env = parseServerEnv();

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Inlined at build time: whether review routes exist is decided by the build, never by the
  // runtime environment of `next start` (a non-secret boolean).
  env: { AEMS_DEV_ROUTES_BUILD: env.AEMS_ENABLE_DEV_ROUTES ? "true" : "false" },
  poweredByHeader: false,
  async headers() {
    const headers = [...SECURITY_HEADERS];
    if (env.NODE_ENV === "production") headers.push(HSTS_HEADER);
    return [{ source: "/:path*", headers }];
  },
};

export default nextConfig;
