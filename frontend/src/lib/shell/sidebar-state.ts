/**
 * Sidebar open/collapsed preference. A UI preference only (never sensitive), stored in a cookie
 * so the server renders the shell in the user's last state without a layout shift.
 */
export const SIDEBAR_COOKIE_NAME = "aems_sidebar";

/** Parse the cookie value; anything other than "false" means expanded (the default). */
export function sidebarDefaultOpen(value: string | undefined): boolean {
  return value !== "false";
}
