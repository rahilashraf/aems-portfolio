import { expect, type Page, test } from "@playwright/test";

import { arrowTo, expectAccessible, isMobile, requireDevRoutes, useTheme } from "./helpers";

requireDevRoutes();

const sidebarState = (page: Page) =>
  page.locator('[data-slot="sidebar"][data-state]').getAttribute("data-state");

async function openNavigation(page: Page) {
  if (isMobile(page)) {
    await page.getByRole("button", { name: "Toggle navigation" }).click();
    return page.getByRole("dialog", { name: "Navigation" });
  }
  return page.locator("body");
}

test.describe("application shell", () => {
  for (const theme of ["light", "dark"] as const) {
    test(`is accessible in every page state (${theme})`, async ({ page }) => {
      await useTheme(page, theme);
      await page.goto("/dev/shell");
      await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
      await expectAccessible(page, `ready ${theme}`);

      await page.getByLabel("Loading").check();
      await expect(
        page.getByRole("status").filter({ hasText: "Loading organization" }),
      ).toBeAttached();
      await expectAccessible(page, `loading ${theme}`);

      await page.getByLabel("Error").check();
      await expect(
        page.getByRole("alert").filter({ hasText: "Something went wrong" }),
      ).toContainText("could not be loaded");
      await expectAccessible(page, `error ${theme}`);
      await page.getByRole("button", { name: "Try again" }).click();
      await expect(page.getByRole("heading", { name: "Your access" })).toBeVisible();

      const scope = await openNavigation(page);
      await expectAccessible(page, `navigation open ${theme}`);
      if (isMobile(page)) await page.keyboard.press("Escape");
      await expect(scope.getByRole("link", { name: "Overview" }).first()).toBeAttached();
    });
  }

  test("permission-aware presentation follows the granted permissions", async ({ page }) => {
    await page.goto("/dev/shell");
    await expect(page.getByRole("heading", { name: "Organization profile" })).toBeVisible();
    await page.getByLabel("organization.view").uncheck();
    await expect(page.getByRole("heading", { name: "Organization profile" })).toHaveCount(0);
    await expect(page.getByText("You don't have access to this")).toBeVisible();
    await expect(page.getByRole("list", { name: "Permissions" })).not.toContainText(
      "organization.view",
    );
  });

  test("switches organization with the keyboard", async ({ page }) => {
    await page.goto("/dev/shell");
    const scope = await openNavigation(page);
    const switcher = scope.getByRole("button", {
      name: /^Northwind Academy School Switch organization$/,
    });
    await switcher.focus();
    await page.keyboard.press("Enter");
    const menu = page.getByRole("menu");
    await expect(menu).toBeVisible();
    await arrowTo(page, menu.getByRole("menuitem", { name: /Lakeside University/ }));
    await page.keyboard.press("Enter");
    await expect(menu).toHaveCount(0);
    await expect(
      scope.getByRole("button", {
        name: /^Lakeside University University Switch organization$/,
      }),
    ).toBeVisible();
    if (!isMobile(page)) {
      await expect(page.getByRole("navigation", { name: "breadcrumb" })).toContainText(
        "Lakeside University",
      );
    }
  });

  test("theme choice from the account menu persists across reloads", async ({ page }) => {
    await useTheme(page, "light");
    await page.goto("/dev/shell");
    const account = isMobile(page)
      ? page.getByRole("banner").getByRole("button", { name: "Account menu" })
      : page.getByRole("button", { name: /Preview User.*Account menu/ });
    await account.click();
    await page.getByRole("menuitemradio", { name: "Dark" }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);
    await page.reload();
    await expect(page.locator("html")).toHaveClass(/dark/);
  });
});

test.describe("desktop sidebar", () => {
  test.skip(({ viewport }) => (viewport?.width ?? 0) < 1024, "Desktop only");

  test("collapses to an icon rail with Ctrl+B and keeps the preference", async ({ page }) => {
    await page.goto("/dev/shell");
    expect(await sidebarState(page)).toBe("expanded");
    await page.keyboard.press("Control+b");
    await expect.poll(() => sidebarState(page)).toBe("collapsed");
    await page.reload();
    expect(await sidebarState(page)).toBe("collapsed");
    // Labels become tooltips on the rail.
    await page.getByRole("link", { name: "Overview" }).focus();
    await expect(page.getByRole("tooltip")).toContainText("Overview");
    await expectAccessible(page, "collapsed rail");
    await page.getByRole("button", { name: "Toggle navigation" }).click();
    await expect.poll(() => sidebarState(page)).toBe("expanded");
  });

  test("keyboard users reach every shell control in order", async ({ page }) => {
    await page.goto("/dev/shell");
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /Switch organization$/ })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Overview" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /Account menu$/ })).toBeFocused();
  });
});

test.describe("mobile navigation", () => {
  test.skip(({ viewport }) => (viewport?.width ?? 0) >= 1024, "Mobile only");

  test("opens as a modal sheet, traps focus, closes on Escape and restores focus", async ({
    page,
  }) => {
    await page.goto("/dev/shell");
    const trigger = page.getByRole("button", { name: "Toggle navigation" });
    await trigger.click();
    const sheet = page.getByRole("dialog", { name: "Navigation" });
    await expect(sheet).toBeVisible();
    for (let i = 0; i < 6; i += 1) {
      await page.keyboard.press("Tab");
      expect(
        await page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null),
      ).toBe(true);
    }
    await page.keyboard.press("Escape");
    await expect(sheet).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test("closes after navigating", async ({ page }) => {
    await page.goto("/dev/shell");
    await page.getByRole("button", { name: "Toggle navigation" }).click();
    await page
      .getByRole("dialog", { name: "Navigation" })
      .getByRole("link", { name: "Overview" })
      .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });
});

test("reduced motion disables transitions and animations", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/dev/shell");
  const durations = await page.evaluate(() =>
    [...document.querySelectorAll("*")]
      .map((element) => getComputedStyle(element))
      .flatMap((style) => [style.transitionDuration, style.animationDuration])
      .flatMap((value) => value.split(",").map((part) => Number.parseFloat(part))),
  );
  expect(Math.max(...durations)).toBeLessThanOrEqual(0.0001);
});
