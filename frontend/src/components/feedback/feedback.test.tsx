import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Inbox } from "lucide-react";
import { describe, expect, it, vi } from "vitest";

import { axeViolations } from "@/test/axe";

import { EmptyState } from "./empty-state";
import { ErrorState } from "./error-state";
import { LoadingState } from "./loading-state";
import { PermissionDenied } from "./permission-denied";
import { SessionSplash } from "./session-splash";

describe("LoadingState", () => {
  it("announces immediately but shows the skeleton only after the delay", () => {
    vi.useFakeTimers();
    try {
      render(<LoadingState label="Loading members" variant="table" rows={3} />);
      const status = screen.getByRole("status");
      expect(status).toHaveAttribute("aria-busy", "true");
      expect(status).toHaveTextContent("Loading members");
      expect(screen.queryByTestId("loading-skeleton")).toBeNull();
      act(() => vi.advanceTimersByTime(150));
      expect(screen.getByTestId("loading-skeleton")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it.each(["page", "card", "table"] as const)("renders the %s skeleton", async (variant) => {
    render(<LoadingState label="Loading" variant={variant} delayMs={0} />);
    expect(await screen.findByTestId("loading-skeleton")).toBeInTheDocument();
  });
});

describe("ErrorState", () => {
  it("shows a safe message, the reference and a working retry", async () => {
    const onRetry = vi.fn();
    const { container } = render(<ErrorState requestId="req-123" onRetry={onRetry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong");
    expect(screen.getByText("req-123")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledOnce();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("omits the retry and reference when not provided", () => {
    render(<ErrorState title="Not loaded" description="Later." />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByText(/Reference/)).toBeNull();
  });
});

describe("EmptyState and PermissionDenied", () => {
  it("renders title, description and an optional action", async () => {
    const { container } = render(
      <EmptyState
        icon={Inbox}
        title="No items"
        description="Nothing yet."
        action={<button type="button">Add</button>}
      />,
    );
    expect(screen.getByText("No items")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("renders the permission message", () => {
    render(<PermissionDenied />);
    expect(screen.getByText("You don't have access to this")).toBeInTheDocument();
  });
});

describe("SessionSplash", () => {
  it("is an announced status with a visually hidden label", () => {
    render(<SessionSplash />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading AEMS");
  });
});
