import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AemsMark, AemsWordmark } from "@/components/brand/aems-mark";
import { SkipLink } from "@/components/skip-link";
import { axeViolations } from "@/test/axe";

import { PageHeader } from "./page-header";
import { PageSection } from "./page-section";

describe("PageHeader", () => {
  it("renders the page's single h1, description and actions", async () => {
    const { container } = render(
      <PageHeader
        title="Overview"
        description="Summary"
        actions={<button type="button">Export</button>}
      />,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    expect(screen.getByText("Summary")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export" })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("omits optional parts", () => {
    const { container } = render(<PageHeader title="Only title" />);
    expect(container.querySelectorAll("p")).toHaveLength(0);
  });
});

describe("PageSection", () => {
  it("is a region labelled by its h2", () => {
    render(
      <PageSection title="Members" description="People" actions={<span>x</span>}>
        <p>content</p>
      </PageSection>,
    );
    expect(screen.getByRole("region", { name: "Members" })).toContainElement(
      screen.getByText("content"),
    );
    expect(screen.getByRole("heading", { level: 2, name: "Members" })).toBeInTheDocument();
  });
});

describe("brand and skip link", () => {
  it("hides the decorative mark and exposes a titled one", () => {
    const { container } = render(
      <>
        <AemsMark />
        <AemsMark title="AEMS logo" />
        <AemsWordmark />
      </>,
    );
    expect(screen.getByRole("img", { name: "AEMS logo" })).toBeInTheDocument();
    expect(container.querySelectorAll('svg[aria-hidden="true"]')).toHaveLength(2);
  });

  it("links to the main landmark", () => {
    render(<SkipLink />);
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute(
      "href",
      "#main",
    );
  });
});
