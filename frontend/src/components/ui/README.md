# Vendored UI primitives (shadcn/ui)

These components are copied from shadcn/ui (`new-york-v4` registry, tag `shadcn@4.23.0`), MIT
licensed; see [`THIRD_PARTY_NOTICES.md`](../../../THIRD_PARTY_NOTICES.md). They are copied rather
than installed so they can be adapted; the shadcn CLI was not used because its registry host is
not reachable from the build environment, so import aliases were rewritten by hand to the paths
in `components.json`.

The files are formatted with the project's Prettier configuration (semicolons, import order), so
compare them with upstream ignoring whitespace and formatting (`git diff -w` or a formatter pass on
both sides) when updating.
Product-specific composition belongs in `src/components/{shell,page,feedback,form,data}`, not here.

## Local modifications

| File                        | Change                                                                                               | Reason                                                                         |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `sidebar.tsx`               | `md:` breakpoint utilities changed to `lg:`                                                          | The sidebar collapses to an off-canvas sheet below `lg` (ADR-0020)             |
| `sidebar.tsx`               | Cookie name from `src/lib/shell/sidebar-state.ts` (`aems_sidebar`), `samesite=lax` added             | Product-specific UI preference cookie                                          |
| `sidebar.tsx`               | Mobile sheet title/description and trigger label reworded ("Navigation", "Toggle navigation")        | Clearer screen-reader announcements                                            |
| `../../hooks/use-mobile.ts` | `MOBILE_BREAKPOINT` 768 → 1024 (exported); `useSyncExternalStore` instead of `setState` in an effect | Matches the `lg` breakpoint; React Compiler lint rules                         |
| `sidebar.tsx`               | `SidebarMenuSkeleton` uses a fixed width instead of `Math.random()`                                  | Render purity (React Compiler lint rules); component unused by AEMS            |
| `sonner.tsx`                | `theme` cast to `NonNullable<…>`                                                                     | Compiles under `exactOptionalPropertyTypes` (no behaviour change)              |
| `sidebar.tsx`               | Mobile sheet `onCloseAutoFocus` returns focus to the `SidebarTrigger`                                | Upstream leaves focus on `body` after closing (no Radix trigger to restore to) |
| all                         | Import aliases rewritten to `@/components/ui`, `@/hooks`, `@/lib/utils`                              | Registry aliases are resolved by the CLI, which was not used                   |
