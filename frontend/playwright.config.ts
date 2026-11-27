import { defineConfig, devices } from "@playwright/test";

/**
 * Browser verification of the FE-1A surface. The server must be a production build
 * (`pnpm build && pnpm start`); review routes require AEMS_ENABLE_DEV_ROUTES=true at build time.
 *
 * PW_CHROMIUM_EXECUTABLE lets a local environment use a pre-installed Chromium; CI installs the
 * browsers that match this Playwright version.
 */
const PORT = Number(process.env.PORT ?? 3100);
const chromiumPath = process.env.PW_CHROMIUM_EXECUTABLE;
const chromiumLaunch = chromiumPath ? { launchOptions: { executablePath: chromiumPath } } : {};

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "off",
  },
  projects: [
    {
      name: "chromium-desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
        ...chromiumLaunch,
      },
    },
    { name: "chromium-mobile", use: { ...devices["Pixel 7"], ...chromiumLaunch } },
    {
      name: "webkit-desktop",
      use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 900 } },
    },
  ],
  webServer: {
    command: `pnpm start -p ${PORT}`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
