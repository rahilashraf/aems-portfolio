"use client";

import { useSidebar } from "@/components/ui/sidebar";

/**
 * Tooltip text for a sidebar button, only while the desktop sidebar is collapsed to its icon rail
 * (the only time labels are hidden). Otherwise no tooltip is mounted: a hidden Radix tooltip that
 * opens on focus still captures Escape, which kept the mobile navigation sheet from closing.
 */
export function useRailTooltip(label: string): string | undefined {
  const { state, isMobile } = useSidebar();
  return state === "collapsed" && !isMobile ? label : undefined;
}
