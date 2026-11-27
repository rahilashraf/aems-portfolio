import { PERMISSION_CODES, type PermissionCode } from "@/lib/permissions";
import { type ShellOrganization, type ShellUser } from "@/lib/shell/types";

/** Fictional data for the development review routes only. Never used by production pages. */
export const PREVIEW_USER: ShellUser = {
  fullName: "Preview User",
  email: "preview.user@example.org",
};

export interface PreviewOrganization extends ShellOrganization {
  readonly slug: string;
  readonly timezone: string;
  readonly roles: readonly string[];
}

export const PREVIEW_ORGANIZATIONS: readonly PreviewOrganization[] = [
  {
    id: "7f6d2a8e-1b2c-4d3e-8f90-a1b2c3d4e5f6",
    name: "Northwind Academy",
    type: "school",
    slug: "northwind-academy",
    timezone: "Europe/London",
    roles: ["Owner"],
  },
  {
    id: "2b9c4e1f-3a5d-4c6e-9b7a-0f1e2d3c4b5a",
    name: "Lakeside University",
    type: "university",
    slug: "lakeside-university",
    timezone: "America/Toronto",
    roles: ["Admin"],
  },
  {
    id: "c3d4e5f6-7a8b-4c9d-8e0f-1a2b3c4d5e6f",
    name: "Harbor Training Institute",
    type: "training",
    slug: "harbor-training",
    timezone: "Asia/Singapore",
    roles: ["Member"],
  },
];

export const ALL_PERMISSIONS: readonly PermissionCode[] = PERMISSION_CODES;
