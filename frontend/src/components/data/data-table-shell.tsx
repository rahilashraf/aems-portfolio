"use client";

import { ChevronLeft, ChevronRight, Inbox } from "lucide-react";
import { type ReactNode } from "react";

import { EmptyState } from "@/components/feedback/empty-state";
import { ErrorState } from "@/components/feedback/error-state";
import { LoadingState } from "@/components/feedback/loading-state";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

export interface DataTableColumn<TRow> {
  id: string;
  header: string;
  cell: (row: TRow) => ReactNode;
  align?: "start" | "end";
  className?: string;
}

/** The backend's page-number pagination (`count`, `page`, `page_size`, `total_pages`). */
export interface DataTablePagination {
  page: number;
  pageSize: number;
  count: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}

interface DataTableShellProps<TRow> {
  /** Accessible table name (visually hidden caption). */
  caption: string;
  columns: readonly DataTableColumn<TRow>[];
  rows: readonly TRow[];
  getRowId: (row: TRow) => string;
  /** Search, filters or actions above the table. Only working controls. */
  toolbar?: ReactNode;
  loading?: boolean;
  error?: { message?: string; requestId?: string | null; onRetry?: () => void } | null;
  empty?: { title: string; description?: string };
  pagination?: DataTablePagination;
  className?: string;
}

/**
 * Presentational table with loading, error, empty and paginated states. Data fetching, searching
 * and sorting are supplied by the feature that uses it (from FE-2); the shell only renders.
 */
export function DataTableShell<TRow>({
  caption,
  columns,
  rows,
  getRowId,
  toolbar,
  loading = false,
  error = null,
  empty = { title: "Nothing to show yet" },
  pagination,
  className,
}: DataTableShellProps<TRow>) {
  let body: ReactNode;
  if (error) {
    body = (
      <ErrorState
        description={error.message ?? "The list could not be loaded."}
        requestId={error.requestId ?? null}
        {...(error.onRetry ? { onRetry: error.onRetry } : {})}
      />
    );
  } else if (loading) {
    body = <LoadingState label={`Loading ${caption.toLowerCase()}`} variant="table" />;
  } else if (rows.length === 0) {
    body = (
      <EmptyState
        icon={Inbox}
        title={empty.title}
        {...(empty.description ? { description: empty.description } : {})}
        className="border"
      />
    );
  } else {
    body = (
      <div className="overflow-hidden rounded-lg border">
        <Table>
          <TableCaption className="sr-only">{caption}</TableCaption>
          <TableHeader className="bg-muted/50">
            <TableRow>
              {columns.map((column) => (
                <TableHead
                  key={column.id}
                  scope="col"
                  className={cn(column.align === "end" && "text-right", column.className)}
                >
                  {column.header}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={getRowId(row)}>
                {columns.map((column) => (
                  <TableCell
                    key={column.id}
                    className={cn(
                      column.align === "end" && "text-right tabular-nums",
                      column.className,
                    )}
                  >
                    {column.cell(row)}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    );
  }

  return (
    <div className={cn("space-y-3", className)}>
      {toolbar ? <div className="flex flex-wrap items-center gap-2">{toolbar}</div> : null}
      {body}
      {pagination && !error && !loading && rows.length > 0 ? (
        <PaginationBar {...pagination} />
      ) : null}
    </div>
  );
}

export function paginationRange(page: number, pageSize: number, count: number): [number, number] {
  if (count === 0) return [0, 0];
  const start = (page - 1) * pageSize + 1;
  return [Math.min(start, count), Math.min(page * pageSize, count)];
}

function PaginationBar({ page, pageSize, count, totalPages, onPageChange }: DataTablePagination) {
  const [first, last] = paginationRange(page, pageSize, count);
  const pages = Math.max(totalPages, 1);
  return (
    <nav
      aria-label="Pagination"
      className="flex flex-wrap items-center justify-between gap-3 text-muted-foreground"
    >
      <p aria-live="polite">
        Showing <span className="text-foreground tabular-nums">{first}</span>–
        <span className="text-foreground tabular-nums">{last}</span> of{" "}
        <span className="text-foreground tabular-nums">{count}</span>
      </p>
      <div className="flex items-center gap-2">
        <span className="tabular-nums">
          Page {page} of {pages}
        </span>
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label="Previous page"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeft aria-hidden="true" />
        </Button>
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label="Next page"
          disabled={page >= pages}
          onClick={() => onPageChange(page + 1)}
        >
          <ChevronRight aria-hidden="true" />
        </Button>
      </div>
    </nav>
  );
}
