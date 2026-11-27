# AEMS frontend

Next.js web application for AEMS. **Phase 1 Frontend, FE-1A:** foundation, design system and
application shell. Not yet connected to the AEMS API (that is FE-1B). Architecture and decisions:
[ADR-0020](../docs/adr/0020-frontend-architecture.md).

## Requirements

- Node.js 24 LTS (`.nvmrc`; `>=22.12` works)
- pnpm 10.28 via corepack: `corepack enable`

## Commands

Run inside `frontend/` (or use the `make fe-*` targets from the repository root).

| Command                                              | Purpose                                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------------ |
| `pnpm install --frozen-lockfile`                     | Install exact pinned versions (strict peer dependencies)                       |
| `AEMS_ENABLE_DEV_ROUTES=true pnpm dev`               | Dev server with the review routes                                              |
| `pnpm format:check` · `pnpm lint` · `pnpm typecheck` | Prettier, ESLint (zero warnings), strict TypeScript                            |
| `pnpm test` · `pnpm test:coverage`                   | Vitest unit and component tests (coverage gates: 85 % overall, 90 % `src/lib`) |
| `pnpm build` · `pnpm start`                          | Production build and server                                                    |
| `pnpm test:browser`                                  | Playwright + axe against a running production build (see below)                |

Browser tests need a production build: `AEMS_ENABLE_DEV_ROUTES=true pnpm build`, then
`E2E_DEV_ROUTES=true pnpm test:browser`. Add `SCREENSHOTS=1` to save review screenshots to
`screenshots/`. Install browsers with `pnpm exec playwright install chromium webkit`, or point
`PW_CHROMIUM_EXECUTABLE` at an existing Chromium.

## Routes

| Route         | Build                              | Content                                                 |
| ------------- | ---------------------------------- | ------------------------------------------------------- |
| `/`           | all                                | Neutral holding page (no controls)                      |
| `/dev/ui`     | `AEMS_ENABLE_DEV_ROUTES=true` only | Component gallery (fictional data)                      |
| `/dev/shell`  | `AEMS_ENABLE_DEV_ROUTES=true` only | Application shell preview with permission/state toggles |
| anything else | all                                | Not-found page                                          |

## Configuration

See [`.env.example`](.env.example). Values are validated when `next.config.ts` loads; invalid
values stop the build or server. No variable is exposed to the browser.

| Variable                 | Default | Purpose                                                       |
| ------------------------ | ------- | ------------------------------------------------------------- |
| `AEMS_ENABLE_DEV_ROUTES` | `false` | Build the review routes; refused when `VERCEL_ENV=production` |

## Structure

- `src/styles/globals.css` holds the design tokens (light/dark, OKLCH), the single source of
  truth; `tokens.test.ts` enforces WCAG AA contrast.
- `src/components/ui/` holds vendored shadcn/ui primitives (MIT, see
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and the local-modification list in its
  README).
- `src/components/{shell,page,feedback,form,data,brand}/` hold AEMS components; the shell is
  presentational (typed props).
- `src/lib/` holds environment validation, permission codes (kept in sync with the backend
  catalog by a test), the navigation registry, breadcrumbs and security headers.

## Licence

Proprietary; see the repository [`LICENSE`](../LICENSE). Third-party code: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
