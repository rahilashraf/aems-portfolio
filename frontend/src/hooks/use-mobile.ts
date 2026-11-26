import * as React from "react";

// AEMS: the sidebar becomes an off-canvas sheet below the `lg` breakpoint (ADR-0020).
export const MOBILE_BREAKPOINT = 1024;

const QUERY = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`;

function subscribe(onChange: () => void) {
  const mql = window.matchMedia(QUERY);
  mql.addEventListener("change", onChange);
  return () => mql.removeEventListener("change", onChange);
}

// AEMS: useSyncExternalStore instead of setState inside an effect (react-hooks v7 rules).
export function useIsMobile() {
  return React.useSyncExternalStore(
    subscribe,
    () => window.matchMedia(QUERY).matches,
    () => false,
  );
}
