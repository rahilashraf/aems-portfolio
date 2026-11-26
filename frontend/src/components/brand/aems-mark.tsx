import { cn } from "@/lib/utils";

/**
 * Neutral AEMS mark: a rounded square with an abstract "A" formed by two strokes and a bar.
 * Decorative by default; pass `title` to expose it to assistive technology.
 */
export function AemsMark({ className, title }: { className?: string; title?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      className={cn("size-8 shrink-0", className)}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      <rect width="32" height="32" rx="8" className="fill-primary" />
      <path
        d="M10 23 16 9l6 14M12.6 18h6.8"
        className="stroke-primary-foreground"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

export function AemsWordmark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <AemsMark />
      <span className="text-base font-semibold tracking-tight">AEMS</span>
    </span>
  );
}
