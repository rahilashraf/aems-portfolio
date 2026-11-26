import { cookies } from "next/headers";

import { SIDEBAR_COOKIE_NAME, sidebarDefaultOpen } from "@/lib/shell/sidebar-state";

import { ShellPreview } from "./shell-preview";

export const metadata = { title: "Shell preview" };

export default async function ShellPreviewPage() {
  const store = await cookies();
  return (
    <ShellPreview defaultSidebarOpen={sidebarDefaultOpen(store.get(SIDEBAR_COOKIE_NAME)?.value)} />
  );
}
