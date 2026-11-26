import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { axeViolations } from "@/test/axe";

import { DataTableShell, paginationRange, type DataTableColumn } from "./data-table-shell";

interface Row {
  id: string;
  name: string;
  count: number;
}

const COLUMNS: DataTableColumn<Row>[] = [
  { id: "name", header: "Name", cell: (row) => row.name },
  { id: "count", header: "Count", cell: (row) => row.count, align: "end" },
];
const ROWS: Row[] = [
  { id: "a", name: "Alpha", count: 3 },
  { id: "b", name: "Beta", count: 7 },
];

describe("DataTableShell", () => {
  it("renders a captioned table with column headers and rows", async () => {
    const { container } = render(
      <DataTableShell caption="Records" columns={COLUMNS} rows={ROWS} getRowId={(row) => row.id} />,
    );
    const table = screen.getByRole("table", { name: "Records" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Name", "Count"]);
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(await axeViolations(container)).toEqual([]);
  });

  it("paginates with working, bounded controls", async () => {
    const onPageChange = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        pagination={{ page: 1, pageSize: 2, count: 5, totalPages: 3, onPageChange }}
      />,
    );
    const nav = screen.getByRole("navigation", { name: "Pagination" });
    expect(nav).toHaveTextContent("Showing 1–2 of 5");
    expect(nav).toHaveTextContent("Page 1 of 3");
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(onPageChange).toHaveBeenCalledWith(2);

    rerender(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={ROWS.slice(0, 1)}
        getRowId={(row) => row.id}
        pagination={{ page: 3, pageSize: 2, count: 5, totalPages: 3, onPageChange }}
      />,
    );
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Previous page" }));
    expect(onPageChange).toHaveBeenLastCalledWith(2);
  });

  it("shows loading, error and empty states instead of the table and pagination", async () => {
    const pagination = { page: 1, pageSize: 2, count: 0, totalPages: 0, onPageChange: vi.fn() };
    const { rerender } = render(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        loading
        pagination={pagination}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Loading records");
    expect(screen.queryByRole("table")).toBeNull();

    const onRetry = vi.fn();
    rerender(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        error={{ requestId: "r-1", onRetry }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("The list could not be loaded.");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();

    rerender(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        empty={{ title: "No records", description: "Nothing matches." }}
        pagination={pagination}
        toolbar={<input aria-label="Search records" />}
      />,
    );
    expect(screen.getByText("No records")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Search records" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Pagination" })).toBeNull();
  });

  it("uses default empty and error copy", () => {
    const { rerender } = render(
      <DataTableShell caption="Records" columns={COLUMNS} rows={[]} getRowId={(row) => row.id} />,
    );
    expect(screen.getByText("Nothing to show yet")).toBeInTheDocument();
    rerender(
      <DataTableShell
        caption="Records"
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        error={{ message: "Boom." }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Boom.");
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("paginationRange", () => {
  it.each([
    [1, 25, 0, [0, 0]],
    [1, 25, 10, [1, 10]],
    [2, 25, 60, [26, 50]],
    [3, 25, 60, [51, 60]],
    [9, 25, 60, [60, 60]],
  ])("page %i size %i of %i → %j", (page, size, count, expected) => {
    expect(paginationRange(page, size, count)).toEqual(expected);
  });
});
