import { expect, test } from "@playwright/test";

import { arrowTo, expectAccessible, requireDevRoutes, useTheme } from "./helpers";

requireDevRoutes();

test.describe("component gallery", () => {
  for (const theme of ["light", "dark"] as const) {
    test(`is accessible (${theme})`, async ({ page }) => {
      await useTheme(page, theme);
      await page.goto("/dev/ui");
      await expect(
        page.getByRole("heading", { level: 1, name: "Component gallery" }),
      ).toBeVisible();
      await expectAccessible(page, `gallery ${theme}`);
    });
  }

  test("dialogs trap focus, close on Escape and restore focus to their trigger", async ({
    page,
  }) => {
    await page.goto("/dev/ui");
    for (const [name, role] of [
      ["Open dialog", "dialog"],
      ["Open confirmation", "alertdialog"],
      ["Open sheet", "dialog"],
    ] as const) {
      const trigger = page.getByRole("button", { name });
      await trigger.click();
      const overlay = page.getByRole(role);
      await expect(overlay).toBeVisible();
      await expectAccessible(page, name);
      for (let i = 0; i < 4; i += 1) {
        await page.keyboard.press("Tab");
        expect(
          await page.evaluate(
            (r) => document.activeElement?.closest(`[role="${r}"]`) !== null,
            role,
          ),
        ).toBe(true);
      }
      await page.keyboard.press("Escape");
      await expect(overlay).toHaveCount(0);
      await expect(trigger).toBeFocused();
    }
  });

  test("menus are keyboard operable", async ({ page }) => {
    await page.goto("/dev/ui");
    const trigger = page.getByRole("button", { name: "Open menu" });
    await trigger.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("menu")).toBeVisible();
    await arrowTo(page, page.getByRole("menuitem", { name: "Second action" }));
    await expect(page.getByRole("menuitem", { name: "Second action" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test("form validation is announced and associated with each field", async ({ page }) => {
    await page.goto("/dev/ui");
    await page.getByRole("button", { name: "Validate" }).click();
    const name = page.getByLabel("Display name");
    await expect(name).toHaveAttribute("aria-invalid", "true");
    await expect(name).toHaveAccessibleDescription(/Enter at least 2 characters\./);
    await expect(page.getByLabel("Email address")).toHaveAccessibleDescription(
      "Enter a valid email address.",
    );
    await expectAccessible(page, "form errors");
    await name.fill("Ada");
    await page.getByLabel("Email address").fill("ada@example.org");
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(name).not.toHaveAttribute("aria-invalid");
    await expect(page.getByText("Form is valid")).toBeVisible();
  });

  test("the data table searches and paginates", async ({ page }) => {
    await page.goto("/dev/ui");
    const pagination = page.getByRole("navigation", { name: "Pagination" });
    await expect(pagination).toContainText("Showing 1–8 of 23");
    await pagination.getByRole("button", { name: "Next page" }).click();
    await expect(pagination).toContainText("Showing 9–16 of 23");
    await page.getByLabel("Search sample records").fill("record 2");
    await expect(pagination).toContainText("of 4");
    await page.getByLabel("Search sample records").fill("zzz");
    await expect(page.getByText("No matching records")).toBeVisible();
    await expect(pagination).toHaveCount(0);
  });
});
