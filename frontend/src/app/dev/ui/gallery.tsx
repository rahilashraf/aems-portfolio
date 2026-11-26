"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Bell, Inbox, Info, Plus, Search, Trash2 } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { AemsWordmark } from "@/components/brand/aems-mark";
import { DataTableShell, type DataTableColumn } from "@/components/data/data-table-shell";
import { EmptyState } from "@/components/feedback/empty-state";
import { ErrorState } from "@/components/feedback/error-state";
import { LoadingState } from "@/components/feedback/loading-state";
import { PermissionDenied } from "@/components/feedback/permission-denied";
import { TextField } from "@/components/form/text-field";
import { PageHeader } from "@/components/page/page-header";
import { PageSection } from "@/components/page/page-section";
import { Breadcrumbs } from "@/components/shell/breadcrumbs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const SWATCHES = [
  "background",
  "card",
  "muted",
  "accent",
  "primary",
  "secondary",
  "destructive",
  "success",
  "warning",
  "info",
  "border",
  "sidebar",
] as const;

const SAMPLE_SCHEMA = z.object({
  displayName: z
    .string()
    .trim()
    .min(2, "Enter at least 2 characters.")
    .max(80, "Use at most 80 characters."),
  email: z.email("Enter a valid email address."),
});
type SampleValues = z.infer<typeof SAMPLE_SCHEMA>;

interface SampleRow {
  id: string;
  name: string;
  category: string;
  items: number;
}

const ROWS: SampleRow[] = Array.from({ length: 23 }, (_, index) => ({
  id: `row-${index + 1}`,
  name: `Sample record ${String(index + 1).padStart(2, "0")}`,
  category: ["Alpha", "Beta", "Gamma"][index % 3]!,
  items: (index * 7) % 40,
}));

const COLUMNS: DataTableColumn<SampleRow>[] = [
  { id: "name", header: "Name", cell: (row) => <span className="font-medium">{row.name}</span> },
  {
    id: "category",
    header: "Category",
    cell: (row) => <Badge variant="secondary">{row.category}</Badge>,
  },
  { id: "items", header: "Items", cell: (row) => row.items, align: "end" },
];

const PAGE_SIZE = 8;

export function Gallery() {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="mx-auto w-full max-w-screen-xl space-y-12 px-4 py-8 outline-none sm:px-6 lg:px-8"
    >
      <div className="space-y-4">
        <Breadcrumbs
          items={[{ label: "Development", href: "/dev/shell" }, { label: "Component gallery" }]}
        />
        <PageHeader
          title="Component gallery"
          description="AEMS design system review. Development builds only; all data is fictional."
          actions={
            <Button asChild variant="outline">
              <Link href="/dev/shell">Open shell preview</Link>
            </Button>
          }
        />
      </div>
      <BrandSection />
      <ButtonsSection />
      <FormSection />
      <FeedbackSection />
      <OverlaysSection />
      <DataSection />
    </main>
  );
}

function BrandSection() {
  return (
    <PageSection
      title="Brand, typography and colour"
      description="Neutral AEMS branding; semantic tokens in light and dark."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardContent className="space-y-3">
            <AemsWordmark />
            <p className="text-2xl font-semibold tracking-tight">Page title · 24/32 semibold</p>
            <p className="text-base font-semibold">Section title · 16 semibold</p>
            <p>Body text · 14 regular, for dense administrative screens.</p>
            <p className="text-xs text-muted-foreground">Caption · 12 muted</p>
            <p className="font-mono text-xs">Monospace · identifiers and references</p>
            <p className="tabular-nums">Tabular numbers · 1,204 · 98.6%</p>
          </CardContent>
        </Card>
        <ul className="grid grid-cols-3 gap-3 sm:grid-cols-4" aria-label="Colour tokens">
          {SWATCHES.map((name) => (
            <li key={name} className="space-y-1.5">
              <div className="h-12 rounded-md border" style={{ background: `var(--${name})` }} />
              <p className="font-mono text-[0.6875rem] text-muted-foreground">{name}</p>
            </li>
          ))}
        </ul>
      </div>
    </PageSection>
  );
}

function ButtonsSection() {
  return (
    <PageSection title="Actions" description="Variants, sizes, icons and busy state.">
      <div className="flex flex-wrap items-center gap-3">
        <Button>Primary</Button>
        <Button variant="secondary">Secondary</Button>
        <Button variant="outline">Outline</Button>
        <Button variant="ghost">Ghost</Button>
        <Button variant="link">Link</Button>
        <Button variant="destructive">
          <Trash2 aria-hidden="true" />
          Delete
        </Button>
        <Button size="sm">
          <Plus aria-hidden="true" />
          Small
        </Button>
        <Button size="icon" aria-label="Notifications">
          <Bell aria-hidden="true" />
        </Button>
        <Button disabled>
          <Spinner aria-hidden="true" />
          Saving
        </Button>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Badge>Default</Badge>
        <Badge variant="secondary">Secondary</Badge>
        <Badge variant="outline">Outline</Badge>
        <Badge variant="destructive">Destructive</Badge>
        <Avatar>
          <AvatarFallback>PU</AvatarFallback>
        </Avatar>
        <span className="text-muted-foreground">
          Toggle the sidebar with <Kbd>Ctrl</Kbd> + <Kbd>B</Kbd>
        </span>
      </div>
    </PageSection>
  );
}

function FormSection() {
  const form = useForm<SampleValues>({
    resolver: zodResolver(SAMPLE_SCHEMA),
    defaultValues: { displayName: "", email: "" },
    mode: "onTouched",
  });
  const onSubmit = form.handleSubmit((values) => {
    toast.success("Form is valid", {
      description: `Preview only: ${values.displayName} was not saved.`,
    });
  });

  return (
    <PageSection
      title="Forms"
      description="Labelled fields, descriptions and Zod validation messages."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <h3 className="text-base">Validated form</h3>
            </CardTitle>
            <CardDescription>
              React Hook Form with a Zod resolver. Nothing is submitted.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} noValidate className="space-y-4">
              <TextField
                control={form.control}
                name="displayName"
                label="Display name"
                description="Shown to other members."
                autoComplete="off"
              />
              <TextField
                control={form.control}
                name="email"
                label="Email address"
                type="email"
                autoComplete="off"
              />
              <Button type="submit">Validate</Button>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="gallery-search">Search</Label>
              <div className="relative">
                <Search
                  className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  id="gallery-search"
                  type="search"
                  placeholder="Search records"
                  className="pl-8"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="gallery-notes">Notes</Label>
              <Textarea id="gallery-notes" rows={3} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="gallery-select">Category</Label>
              <Select>
                <SelectTrigger id="gallery-select" className="w-full">
                  <SelectValue placeholder="Choose a category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="alpha">Alpha</SelectItem>
                  <SelectItem value="beta">Beta</SelectItem>
                  <SelectItem value="gamma">Gamma</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="gallery-check" />
              <Label htmlFor="gallery-check">Include archived records</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="gallery-switch" />
              <Label htmlFor="gallery-switch">Compact rows</Label>
            </div>
            <RadioGroup defaultValue="all" aria-label="Visibility">
              {["all", "active", "inactive"].map((value) => (
                <div key={value} className="flex items-center gap-2">
                  <RadioGroupItem id={`gallery-radio-${value}`} value={value} />
                  <Label htmlFor={`gallery-radio-${value}`} className="capitalize">
                    {value}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </CardContent>
        </Card>
      </div>
    </PageSection>
  );
}

function FeedbackSection() {
  return (
    <PageSection
      title="Feedback"
      description="Alerts, toasts, empty, error, permission and loading states."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <Alert role="note">
          <Info aria-hidden="true" />
          <AlertTitle>Information</AlertTitle>
          <AlertDescription>Neutral, non-blocking context for the current page.</AlertDescription>
        </Alert>
        <Alert variant="destructive">
          <Info aria-hidden="true" />
          <AlertTitle>Action required</AlertTitle>
          <AlertDescription>Reserved for problems the user must address.</AlertDescription>
        </Alert>
        <Card>
          <CardContent>
            <EmptyState
              icon={Inbox}
              title="Nothing here yet"
              description="Items appear here once they exist."
            />
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <PermissionDenied />
          </CardContent>
        </Card>
        <ErrorState
          requestId="0f9e8d7c-preview"
          onRetry={() => toast("Retry requested", { description: "Preview only." })}
        />
        <Card>
          <CardContent>
            <LoadingState label="Loading example" delayMs={0} />
          </CardContent>
        </Card>
      </div>
      <div className="flex flex-wrap gap-3">
        <Button
          variant="outline"
          onClick={() => toast.success("Saved", { description: "Preview toast." })}
        >
          Show success toast
        </Button>
        <Button
          variant="outline"
          onClick={() => toast.error("Could not save", { description: "Preview toast." })}
        >
          Show error toast
        </Button>
      </div>
    </PageSection>
  );
}

function OverlaysSection() {
  return (
    <PageSection
      title="Overlays"
      description="Focus is trapped while open and restored on close; Escape closes."
    >
      <div className="flex flex-wrap gap-3">
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="outline">Open dialog</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Dialog title</DialogTitle>
              <DialogDescription>Dialogs hold short, focused tasks.</DialogDescription>
            </DialogHeader>
            <div className="space-y-2">
              <Label htmlFor="dialog-name">Name</Label>
              <Input id="dialog-name" />
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Close</Button>
              </DialogClose>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="outline">Open confirmation</Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Confirm the action?</AlertDialogTitle>
              <AlertDialogDescription>
                Confirmations protect destructive or irreversible actions.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction>Confirm</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
        <Sheet>
          <SheetTrigger asChild>
            <Button variant="outline">Open sheet</Button>
          </SheetTrigger>
          <SheetContent>
            <SheetHeader>
              <SheetTitle>Sheet title</SheetTitle>
              <SheetDescription>Side panels for secondary detail.</SheetDescription>
            </SheetHeader>
          </SheetContent>
        </Sheet>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline">Open menu</Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Actions</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onSelect={() => toast("First action", { description: "Preview only." })}
            >
              First action
            </DropdownMenuItem>
            <DropdownMenuItem
              onSelect={() => toast("Second action", { description: "Preview only." })}
            >
              Second action
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline">Open popover</Button>
          </PopoverTrigger>
          <PopoverContent>Popovers show light, contextual detail.</PopoverContent>
        </Popover>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="outline">Hover or focus</Button>
          </TooltipTrigger>
          <TooltipContent>Tooltips label icon-only controls.</TooltipContent>
        </Tooltip>
      </div>
      <Tabs defaultValue="first" className="max-w-xl">
        <TabsList>
          <TabsTrigger value="first">First</TabsTrigger>
          <TabsTrigger value="second">Second</TabsTrigger>
        </TabsList>
        <TabsContent value="first" className="text-muted-foreground">
          Tabs switch between related views.
        </TabsContent>
        <TabsContent value="second" className="text-muted-foreground">
          Arrow keys move between tabs.
        </TabsContent>
      </Tabs>
    </PageSection>
  );
}

function DataSection() {
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const filtered = useMemo(
    () => ROWS.filter((row) => row.name.toLowerCase().includes(query.trim().toLowerCase())),
    [query],
  );
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, totalPages);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);

  return (
    <PageSection
      title="Data table"
      description="Toolbar, table, empty state and page-number pagination (fixture data)."
    >
      <DataTableShell
        caption="Sample records"
        columns={COLUMNS}
        rows={rows}
        getRowId={(row) => row.id}
        toolbar={
          <div className="w-full max-w-xs">
            <Label htmlFor="table-search" className="sr-only">
              Search sample records
            </Label>
            <Input
              id="table-search"
              type="search"
              placeholder="Search sample records"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
            />
          </div>
        }
        empty={{ title: "No matching records", description: "Try a different search." }}
        pagination={{
          page: current,
          pageSize: PAGE_SIZE,
          count: filtered.length,
          totalPages,
          onPageChange: setPage,
        }}
      />
    </PageSection>
  );
}
