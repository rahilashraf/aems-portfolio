import { mkdirSync } from "node:fs";

import { expect, test } from "@playwright/test";

import { DEV_ROUTES, useTheme } from "./helpers";

/**
 * Review screenshots (desktop and mobile, light and dark). Opt-in: SCREENSHOTS=1. Saved to
 * `screenshots/` and uploaded as a CI artifact; not compared (no visual-regression baseline).
 */
test.skip(process.env.SCREENSHOTS !== "1", "Set SCREENSHOTS=1 to capture review screenshots");
test.skip(({ browserName }) => browserName !== "chromium", "Captured once, with Chromium");
test.use({ deviceScaleFactor: 2 });

const PAGES = [
  { path: "/", name: "holding", fullPage: false, dev: false },
  { path: "/dev/shell", name: "shell", fullPage: false, dev: true },
  { path: "/dev/ui", name: "gallery", fullPage: true, dev: true },
];

for (const theme of ["light", "dark"] as const) {
  for (const target of PAGES) {
    test(`${target.name} (${theme})`, async ({ page }, info) => {
      test.skip(target.dev && !DEV_ROUTES, "Requires review routes");
      mkdirSync("screenshots", { recursive: true });
      await useTheme(page, theme);
      await page.goto(target.path);
      await expect(page.locator("h1").first()).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      const device = info.project.name.includes("mobile") ? "mobile" : "desktop";
      await page.screenshot({
        path: `screenshots/${target.name}-${device}-${theme}.png`,
        fullPage: target.fullPage,
        animations: "disabled",
      });
    });
  }
}

test("mobile navigation open (light)", async ({ page }, info) => {
  test.skip(!DEV_ROUTES || !info.project.name.includes("mobile"), "Mobile review build only");
  mkdirSync("screenshots", { recursive: true });
  await useTheme(page, "light");
  await page.goto("/dev/shell");
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await expect(page.getByRole("dialog", { name: "Navigation" })).toBeVisible();
  await page.screenshot({
    path: "screenshots/shell-mobile-navigation-light.png",
    animations: "disabled",
  });
});
