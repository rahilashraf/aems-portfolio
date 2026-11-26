import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LOADING_INDICATOR_DELAY_MS, useDelayedVisibility } from "./use-delayed-visibility";

describe("useDelayedVisibility", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("stays hidden until the delay elapses", () => {
    const { result } = renderHook(() => useDelayedVisibility(true));
    expect(result.current).toBe(false);
    act(() => vi.advanceTimersByTime(LOADING_INDICATOR_DELAY_MS - 1));
    expect(result.current).toBe(false);
    act(() => vi.advanceTimersByTime(1));
    expect(result.current).toBe(true);
  });

  it("never shows for work that finishes before the delay, and resets when inactive", () => {
    const { result, rerender } = renderHook(({ active }) => useDelayedVisibility(active, 100), {
      initialProps: { active: true },
    });
    act(() => vi.advanceTimersByTime(50));
    rerender({ active: false });
    act(() => vi.advanceTimersByTime(200));
    expect(result.current).toBe(false);

    rerender({ active: true });
    act(() => vi.advanceTimersByTime(100));
    expect(result.current).toBe(true);
    rerender({ active: false });
    expect(result.current).toBe(false);
  });
});
