/** Data the application shell renders. FE-1B fills these from the API; FE-1A uses fixtures. */

export const ORGANIZATION_TYPES = ["school", "university", "training", "other"] as const;
export type OrganizationType = (typeof ORGANIZATION_TYPES)[number];

export interface ShellUser {
  readonly fullName: string;
  readonly email: string;
}

export interface ShellOrganization {
  readonly id: string;
  readonly name: string;
  readonly type: OrganizationType;
}
