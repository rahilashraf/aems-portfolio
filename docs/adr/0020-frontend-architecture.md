# ADR-0020: Frontend architecture (Phase 1 Frontend)

- **Status:** Part 1 (FE-1A) accepted pending review; Part 2 (FE-1B) to be added by the FE-1B batch
- **Date:** 2026-11-26

## Context

The Phase 1 backend foundation is complete (ADR-0001 to ADR-0019). Phase 1 Frontend delivers the
web application in two independently reviewed checkpoints:

- **FE-1A** (this part): Next.js foundation, design system, shared components, a responsive
  application shell, environment configuration and CI. It has no API integration.
- **FE-1B**: same-origin API proxy, session bootstrap, organization context, the organization chooser
  and read-only overview, the nonce-based Content Security Policy and real-backend end-to-end tests.
- **FE-2** (later): sign-in, sign-out and password-management UI.

The interface follows the owner's established administrative style: clean, minimal and dense,
responsive and interactive, without gradients, dashboard filler or non-functional controls. It is
reproduced as a design philosophy only; no code from other projects was used.

## Decision (Part 1: FE-1A)

### Stack and versions

Dependencies were revalidated against the npm registry on 2026-11-26.

- **Pinning policy:** exact versions; the newest patch of each approved major that was at least
  14 days old; installed with `strict-peer-dependencies`, so any peer conflict fails the install.

| Area | Packages (exact pins) | Notes |
|---|---|---|
| Runtime | Node.js 24 LTS (`engines >=22.12 <25`), pnpm 10.28.0 (`packageManager`) | |
| Framework | `next` 16.4.6, `react`/`react-dom` 19.3.1 | App Router, Turbopack builds |
| Language | `typescript` 6.0.3 | **Not 7.x:** `typescript-eslint` 8.72 (used by `eslint-config-next`) requires `<6.1.0` |
| Styling | `tailwindcss`/`@tailwindcss/postcss` 4.3.5, `tw-animate-css` 1.4.0, `class-variance-authority` 0.7.1, `clsx` 2.1.1, `tailwind-merge` 3.7.0 | |
| Components | `radix-ui` 1.8.1; shadcn/ui primitives vendored from tag `shadcn@4.23.0`; `lucide-react` 1.72.0; `next-themes` 0.4.6; `sonner` 2.0.8 | See "Vendored primitives" |
| Forms | `react-hook-form` 7.92.0, `zod` 4.6.7, `@hookform/resolvers` 7.0.6 | |
| Tests | `vitest`/`@vitest/coverage-v8` 5.1.0, `vite` 8.3.8, `@vitejs/plugin-react` 6.3.0, `jsdom` 31.0.0, Testing Library, `axe-core` 4.14.0, `@playwright/test` 1.65.0, `@axe-core/playwright` 4.14.0 | |
| Lint and format | `eslint` **9.39.5**, `eslint-config-next` 16.4.6, `prettier` 3.10.1, `prettier-plugin-tailwindcss` 0.8.1 | **Not ESLint 10:** the newest `eslint-plugin-react` 7.37.5, `jsx-a11y` 6.10.2 and `import` 2.32.0 do not declare ESLint 10 support. ESLint 9 is end-of-life upstream; it is development tooling only (no runtime exposure). Revisit when the plugins support 10 |

- **Deferred to FE-1B, with the API layer:** TanStack Query.
- **Rejected:** `vitest-axe` (unmaintained since 2022; `axe-core` is used directly) and
  `openapi-typescript` (its peer is TypeScript 5 only; FE-1B uses hand-written Zod schemas with an
  OpenAPI contract test).
- **Dependabot** ignores the TypeScript, ESLint and `@types/node` majors until these constraints
  change.

### Structure

```
frontend/
├── src/app/            routes: holding page `/`, not-found, error boundaries, robots;
│                       dev/ (review routes, build-flagged)
├── src/components/ui/  vendored shadcn/ui primitives (MIT)
├── src/components/{brand,feedback,page,form,data,shell}/   AEMS components
├── src/hooks/          use-mobile (vendored), use-delayed-visibility
├── src/lib/            env, permissions, navigation, shell types/format, security headers
├── src/styles/         globals.css (design tokens) + contrast test
└── e2e/                Playwright suite
```

### Design system

- **Tokens** are CSS variables in `src/styles/globals.css`, the single source of truth, exposed to
  Tailwind with `@theme inline`.
  - Colours are OKLCH with light and dark values: surfaces, a neutral indigo-slate `primary`,
    semantic `destructive`/`success`/`warning`/`info`, and sidebar tokens.
  - Also defined: radius scale (0.5 rem base), motion (120/180 ms).
  - A unit test parses this file and enforces WCAG AA contrast for every foreground/background
    pair in both themes (≥ 4.5:1 for text, ≥ 3:1 for the focus ring).
- **Typography:** Geist and Geist Mono via `next/font/google`, downloaded at build time and
  self-hosted. Body text is 14 px for administrative density; page titles are 24 px semibold.
- **Themes:** Light, Dark and System through `next-themes` (`class` strategy), persisted per
  browser, with no flash on load.
- **Motion:** opacity and transform only. `prefers-reduced-motion` disables every transition and
  animation (browser-tested). Loading skeletons appear only after 150 ms, so fast responses never
  flash.
- **Future organization branding** may override only `--primary`, `--primary-foreground`, `--ring`
  and `--sidebar-primary*` under a scoped `[data-org-theme]` attribute. No branding code exists yet.

### Vendored primitives

shadcn/ui components are copied into `src/components/ui` (MIT, `THIRD_PARTY_NOTICES.md`) rather
than generated by the shadcn CLI, because the registry host is not reachable from the build
environment. They come from the same tag the CLI version would use, with import aliases rewritten.

Local modifications are listed in `src/components/ui/README.md`. Notable ones:

- the `lg` breakpoint for the off-canvas sidebar;
- the `aems_sidebar` preference cookie, with `SameSite=Lax`;
- React Compiler lint fixes;
- returning focus to the sidebar trigger when the mobile sheet closes (upstream left focus on
  `body`).

### Application shell

- **`AppShell`** is presentational. It renders the user, organizations and navigation it is given
  (typed `ShellUser`, `ShellOrganization`, `NavGroup`); FE-1B supplies them from the API.
- **Sidebar:**
  - collapses to an icon rail (Ctrl/⌘+B, persisted);
  - becomes a modal sheet below `lg` that traps focus, closes on navigation or Escape and returns
    focus to its trigger;
  - holds the organization switcher at the top and the account menu at the bottom.
- **Header:** sidebar trigger, breadcrumbs (only the current page below `md`), and the account menu
  below `lg`.
- **Navigation registry** (`organizationNavigation`): only shipped destinations are listed. FE-1 has
  **Overview** only; later batches add entries with `requires`. `filterNavigation` removes items
  whose permissions are not all held, so they are absent, not disabled. Permission codes are typed
  over the backend catalog, and a test fails if `backend/apps/rbac/catalog.py` and the frontend
  diverge. Permissions only affect presentation; the API enforces them.
- **Account menu:** identity plus Light/Dark/System. Sign-out and password management arrive in
  FE-2; no inactive entries are shown before then.
- **Accessibility:**
  - Skip link, `header`/`nav`/`main` landmarks, `aria-current`, visible focus rings.
  - Label-in-name compliance (WCAG 2.5.3) for the switcher and account buttons, whose visible text
    is their accessible name.
  - Tooltips mount only on the collapsed desktop rail. A hidden tooltip that opens on focus
    otherwise captured Escape and kept the mobile sheet open, a defect found and fixed in browser
    testing.

### Production surface and review routes

- **FE-1A production build** exposes only:
  - a neutral holding page with no controls;
  - not-found and error boundaries (with a digest reference, never error details);
  - `robots.txt`, which disallows everything (all pages are `noindex`).
- **Review routes** `/dev/ui` (component gallery) and `/dev/shell` (shell preview with fictional
  fixture data and permission and state toggles) exist only when the build sets
  `AEMS_ENABLE_DEV_ROUTES=true`.
  - `next.config.ts` inlines the validated flag at build time, so `next start` cannot enable them
    at runtime.
  - Production builds answer 404; CI verifies this with `curl`.
  - The flag is refused when `VERCEL_ENV=production`.

### Configuration and headers

- **Environment:** `src/lib/env.ts` (Zod) validates the environment when `next.config.ts` loads,
  so invalid values stop `dev`, `build` and `start`. There are no `NEXT_PUBLIC_*` variables;
  nothing is exposed to the browser.
- **Baseline headers** on every response:
  - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`;
  - `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`;
  - `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`;
  - `X-DNS-Prefetch-Control: off`;
  - HSTS (two years) in production;
  - no `X-Powered-By`.

  The nonce-based CSP is FE-1B (it needs the request proxy).

### Testing and CI

- **Unit and component tests** (Vitest, jsdom): library modules, hooks, feedback/page/form/data
  components and the shell (keyboard, theme, sidebar persistence, mobile sheet), with axe checks
  on rendered markup.
  - Coverage gates: 85 % overall, 90 % for `src/lib/**`.
  - Excluded from coverage: vendored primitives and route files, which the browser suite covers.
- **Browser tests** (Playwright with axe, WCAG 2.2 A/AA): desktop Chromium, mobile Chromium
  (Pixel 7) and desktop WebKit. They cover:
  - the production surface;
  - review routes in both themes and every page state;
  - keyboard paths, focus trapping and restoration, menus, form errors, table search and
    pagination;
  - reduced motion;
  - review screenshots (desktop and mobile, light and dark), uploaded as CI artifacts.
- **`Frontend CI`** (`.github/workflows/frontend-ci.yml`): no path filters, read-only token,
  SHA-pinned actions.

  | Job | Contents |
  |---|---|
  | Frontend lint & type check | Prettier check, ESLint, strict TypeScript |
  | Frontend unit & component tests | Vitest with coverage gates |
  | Frontend production build | Invalid-config refusal, build, production-surface and header smoke checks |
  | Frontend browser & accessibility tests | Playwright across browsers with axe, screenshots |
  | Frontend dependency audit | `pnpm audit` |
  | Frontend CI result | Aggregator; recommending it as a required check is the owner's decision |

### Not in FE-1A

TanStack Query and the API client, the proxy, sessions, organization data, CSP, real-backend E2E
(FE-1B); authentication UI (FE-2); any Phase 2 feature.

## FE-1B provisional decisions (recorded, not implemented)

- **Same-origin proxy:** `/api/v1/*` is proxied through the Next.js origin, provisionally by a
  Route Handler that drops client-supplied forwarding headers and sets one controlled
  `X-Forwarded-For`.
- **Must be verified against the actual deployment architecture before production use:**
  - client-IP forwarding and `DJANGO_TRUSTED_PROXY_COUNT`;
  - origin lock-down or proxy authentication;
  - CSRF (`DJANGO_CSRF_TRUSTED_ORIGINS`), cookies, Host/Origin forwarding and trailing slashes.
- **Access tokens** stay in memory only; multi-tab refresh is serialized with Web Locks.

## Alternatives considered

- **shadcn CLI generation:** not possible from the build environment; vendoring from the tagged
  source is equivalent and auditable.
- **TypeScript 7, ESLint 10:** blocked by peer ranges in `typescript-eslint` and the
  `eslint-config-next` plugins (verified with strict peer installation).
- **Runtime flag for review routes:** rejected; a build-time decision cannot be flipped on a
  production server.
- **A CSS-in-JS or component library with its own theme system:** rejected in favour of Tailwind
  tokens plus unstyled Radix primitives, which keep the bundle small and the design in one place.

## Consequences

- FE-1B builds on typed, presentational shell interfaces without restructuring.
- The design tokens and contrast test constrain future colour changes to accessible values.
- Two tooling pins (TypeScript 6, ESLint 9) need revisiting when upstream support lands.
