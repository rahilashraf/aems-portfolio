import { expect, test } from "@playwright/test";

import { expectAccessible, useTheme } from "./helpers";

test.describe("production surface", () => {
  for (const theme of ["light", "dark"] as const) {
    test(`holding page has no controls and is accessible (${theme})`, async ({ page }) => {
      await useTheme(page, theme);
      const response = await page.goto("/");
      expect(response?.status()).toBe(200);
      await expect(page.getByRole("heading", { level: 1, name: "AEMS" })).toBeVisible();
      await expect(page.getByText("not yet connected to the AEMS service")).toBeVisible();
      // Only the skip link; no buttons, form controls or other links.
      await expect(page.getByRole("button")).toHaveCount(0);
      await expect(page.getByRole("textbox")).toHaveCount(0);
      await expect(page.getByRole("link")).toHaveCount(1);
      await expect(page.locator("html")).toHaveClass(new RegExp(theme));
      await expectAccessible(page, `holding ${theme}`);
    });
  }

  test("responses carry the baseline security headers and are not indexed", async ({ page }) => {
    const response = await page.goto("/");
    const headers = response!.headers();
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(headers["permissions-policy"]).toContain("camera=()");
    expect(headers["strict-transport-security"]).toContain("max-age=");
    expect(headers["x-powered-by"]).toBeUndefined();
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
    const robots = await page.request.get("/robots.txt");
    expect(await robots.text()).toContain("Disallow: /");
  });

  test("unknown pages render the accessible not-found page", async ({ page }) => {
    const response = await page.goto("/no-such-page");
    expect(response?.status()).toBe(404);
    await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeAttached();
    await page.getByRole("link", { name: "Go to the start page" }).click();
    await expect(page).toHaveURL("/");
    await expectAccessible(page, "not-found");
  });

  test("the skip link is the first focus stop and moves focus to main", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to main content" });
    await expect(skip).toBeFocused();
    await expect(skip).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();
  });
});
