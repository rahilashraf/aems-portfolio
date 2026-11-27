import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Providers } from "./providers";

describe("Providers", () => {
  it("renders children with the theme set on <html>", async () => {
    render(
      <Providers>
        <p>content</p>
      </Providers>,
    );
    expect(screen.getByText("content")).toBeInTheDocument();
    // System theme in the test environment resolves to light.
    expect(document.documentElement.className).toMatch(/light|dark/);
  });
});
