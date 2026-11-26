import axe from "axe-core";

/**
 * Run axe against rendered markup. Colour contrast is disabled here because jsdom does not
 * compute styles; contrast is verified from the tokens (tokens.test.ts) and in real browsers.
 */
export async function axeViolations(container: Element): Promise<string[]> {
  const results = await axe.run(container, {
    rules: { "color-contrast": { enabled: false }, region: { enabled: false } },
  });
  return results.violations.map((violation) => `${violation.id}: ${violation.help}`);
}
