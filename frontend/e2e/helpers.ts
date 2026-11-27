import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

/** The server under test was built with AEMS_ENABLE_DEV_ROUTES=true. */
export const DEV_ROUTES = process.env.E2E_DEV_ROUTES === "true";

export function requireDevRoutes() {
  test.skip(!DEV_ROUTES, "Requires a build with AEMS_ENABLE_DEV_ROUTES=true");
}

/** WCAG 2.2 A/AA audit of the current page; any violation fails the test. */
export async function expectAccessible(page: Page, context = "") {
  // Audit the settled UI, not an element half-way through an enter animation.
  // Infinite animations (skeleton pulse, spinners) are excluded: they never finish.
  // allSettled: an animation cancelled mid-wait (e.g. an element unmounted by React) rejects
  // `finished` with AbortError in WebKit; a cancelled animation is settled for our purposes.
  await page.evaluate(() =>
    Promise.allSettled(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished),
    ),
  );
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  const summary = results.violations.map(
    (violation) =>
      `${violation.id} (${violation.impact}): ${violation.nodes.map((node) => node.target.join(" ")).join(", ")}`,
  );
  expect(summary, `axe violations ${context}`).toEqual([]);
}

/** Choose the theme the way a user does (stored by next-themes) before the page loads. */
export async function useTheme(page: Page, theme: "light" | "dark" | "system") {
  // Seed once per test; a later choice made in the UI must survive reloads.
  await page.addInitScript((value) => {
    if (window.localStorage.getItem("theme") === null) window.localStorage.setItem("theme", value);
  }, theme);
}

/** Press ArrowDown until `target` has focus (menus may open with or without a focused item). */
export async function arrowTo(page: Page, target: ReturnType<Page["getByRole"]>, maxSteps = 6) {
  for (let step = 0; step < maxSteps; step += 1) {
    if (await target.evaluate((element) => element === document.activeElement)) return;
    await page.keyboard.press("ArrowDown");
  }
  await expect(target).toBeFocused();
}

export function isMobile(page: Page): boolean {
  return (page.viewportSize()?.width ?? 1440) < 1024;
}
