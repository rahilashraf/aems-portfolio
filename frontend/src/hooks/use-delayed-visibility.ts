"use client";

import { useEffect, useState } from "react";

/** Default delay before a loading indicator appears, so fast loads never flash a skeleton. */
export const LOADING_INDICATOR_DELAY_MS = 150;

/** `true` only after `active` has stayed true for `delayMs`; resets as soon as it is inactive. */
export function useDelayedVisibility(
  active: boolean,
  delayMs = LOADING_INDICATOR_DELAY_MS,
): boolean {
  const [elapsed, setElapsed] = useState(false);
  useEffect(() => {
    if (!active) return undefined;
    const timer = window.setTimeout(() => setElapsed(true), delayMs);
    return () => {
      window.clearTimeout(timer);
      setElapsed(false);
    };
  }, [active, delayMs]);
  return active && elapsed;
}
