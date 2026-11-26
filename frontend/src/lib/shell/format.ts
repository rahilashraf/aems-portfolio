import { type OrganizationType } from "./types";

const TYPE_LABELS: Record<OrganizationType, string> = {
  school: "School",
  university: "University",
  training: "Training provider",
  other: "Organization",
};

export function organizationTypeLabel(type: OrganizationType): string {
  return TYPE_LABELS[type];
}

/**
 * Up to two initials for an avatar: first letters of the first and last words of `name`, or the
 * first letter of `fallback` (e.g. an email address). Letters only, upper-cased.
 */
export function initials(name: string, fallback = ""): string {
  const words = name
    .trim()
    .split(/\s+/)
    .map((word) => word.replace(/[^\p{L}\p{N}]/gu, ""))
    .filter(Boolean);
  const first = words[0]?.[0];
  if (first === undefined) {
    return (fallback.trim()[0] ?? "?").toUpperCase();
  }
  const last = words.length > 1 ? words[words.length - 1]?.[0] : undefined;
  return `${first}${last ?? ""}`.toUpperCase();
}
