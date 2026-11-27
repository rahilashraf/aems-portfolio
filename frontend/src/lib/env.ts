import { z } from "zod";

/**
 * Server and build-time configuration (FE-1A). Validated when `next.config.ts` loads, so an
 * invalid value fails `next dev`, `next build` and `next start` instead of running misconfigured.
 *
 * FE-1A defines no `NEXT_PUBLIC_*` variables: nothing is exposed to the browser. The API origin
 * (`AEMS_API_ORIGIN`) arrives with the same-origin proxy in FE-1B.
 */
const flag = z
  .enum(["true", "false"], { error: 'Expected "true" or "false".' })
  .optional()
  .transform((value) => value === "true");

export const serverEnvSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    /** Enables the development-only review routes (/dev/ui, /dev/shell). Off by default. */
    AEMS_ENABLE_DEV_ROUTES: flag,
    /** Set by Vercel: "production" for the production deployment. */
    VERCEL_ENV: z.enum(["production", "preview", "development"]).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.AEMS_ENABLE_DEV_ROUTES && env.VERCEL_ENV === "production") {
      ctx.addIssue({
        code: "custom",
        path: ["AEMS_ENABLE_DEV_ROUTES"],
        message: "Development review routes must not be enabled in a production deployment.",
      });
    }
  });

export type ServerEnv = z.infer<typeof serverEnvSchema>;

/** Parse and validate the environment; throws with every problem listed. */
export function parseServerEnv(
  source: Record<string, string | undefined> = process.env,
): ServerEnv {
  const result = serverEnvSchema.safeParse(source);
  if (!result.success) {
    throw new Error(`Invalid AEMS frontend configuration:\n${z.prettifyError(result.error)}`);
  }
  return result.data;
}

/**
 * True only when the build enabled the development review routes. `next.config.ts` inlines the
 * validated AEMS_ENABLE_DEV_ROUTES value as AEMS_DEV_ROUTES_BUILD, so the decision is fixed at
 * build time and cannot be switched on by the runtime environment.
 */
export function devRoutesEnabled(
  buildFlag: string | undefined = process.env.AEMS_DEV_ROUTES_BUILD,
): boolean {
  return buildFlag === "true";
}
