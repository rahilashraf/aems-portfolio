import { expect, test } from "@playwright/test";

import { DEV_ROUTES } from "./helpers";

test("review routes exist only in builds that enable them", async ({ page }) => {
  for (const path of ["/dev/ui", "/dev/shell"]) {
    const response = await page.goto(path);
    expect(response?.status(), path).toBe(DEV_ROUTES ? 200 : 404);
  }
});
