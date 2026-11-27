"use client";

import { Info } from "lucide-react";
import { useMemo, useState } from "react";

import { ErrorState } from "@/components/feedback/error-state";
import { LoadingState } from "@/components/feedback/loading-state";
import { PermissionDenied } from "@/components/feedback/permission-denied";
import { PageHeader } from "@/components/page/page-header";
import { PageSection } from "@/components/page/page-section";
import { AppShell } from "@/components/shell/app-shell";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { filterNavigation, organizationNavigation } from "@/lib/navigation/nav";
import { createPermissionChecker, type PermissionCode } from "@/lib/permissions";
import { organizationTypeLabel } from "@/lib/shell/format";

import { ALL_PERMISSIONS, PREVIEW_ORGANIZATIONS, PREVIEW_USER } from "../_preview/fixtures";

const BASE_PATH = "/dev/shell";
type PreviewState = "ready" | "loading" | "error";

export function ShellPreview({ defaultSidebarOpen }: { defaultSidebarOpen: boolean }) {
  const [organizationId, setOrganizationId] = useState(PREVIEW_ORGANIZATIONS[0]!.id);
  const [granted, setGranted] = useState<ReadonlySet<PermissionCode>>(new Set(ALL_PERMISSIONS));
  const [state, setState] = useState<PreviewState>("ready");

  const organization =
    PREVIEW_ORGANIZATIONS.find((candidate) => candidate.id === organizationId) ??
    PREVIEW_ORGANIZATIONS[0]!;
  const can = useMemo(() => createPermissionChecker(granted), [granted]);
  const navigation = useMemo(() => filterNavigation(organizationNavigation(BASE_PATH), can), [can]);

  const toggle = (code: PermissionCode, checked: boolean) => {
    setGranted((previous) => {
      const next = new Set(previous);
      if (checked) next.add(code);
      else next.delete(code);
      return next;
    });
  };

  return (
    <AppShell
      user={PREVIEW_USER}
      organization={organization}
      organizations={PREVIEW_ORGANIZATIONS}
      navigation={navigation}
      onSelectOrganization={setOrganizationId}
      breadcrumbs={[{ label: organization.name, href: BASE_PATH }, { label: "Overview" }]}
      defaultSidebarOpen={defaultSidebarOpen}
    >
      <Alert role="note">
        <Info aria-hidden="true" />
        <AlertTitle>Development preview</AlertTitle>
        <AlertDescription>
          Fixture data only. This page is not connected to the AEMS API and does not exist in
          production builds.
        </AlertDescription>
      </Alert>

      <PageHeader title="Overview" description="Organization profile and your access." />

      {state === "loading" ? (
        <LoadingState label="Loading organization" variant="page" delayMs={0} />
      ) : null}
      {state === "error" ? (
        <ErrorState
          description="The organization could not be loaded."
          requestId="3f1c2a9e-preview"
          onRetry={() => setState("ready")}
        />
      ) : null}
      {state === "ready" ? (
        <div className="grid gap-4 md:grid-cols-2">
          {can("organization.view") ? (
            <Card>
              <CardHeader>
                <CardTitle>
                  <h2 className="text-base">Organization profile</h2>
                </CardTitle>
                <CardDescription>Details of {organization.name}.</CardDescription>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2">
                  <dt className="text-muted-foreground">Name</dt>
                  <dd>{organization.name}</dd>
                  <dt className="text-muted-foreground">Type</dt>
                  <dd>{organizationTypeLabel(organization.type)}</dd>
                  <dt className="text-muted-foreground">Identifier</dt>
                  <dd className="font-mono text-xs leading-5">{organization.slug}</dd>
                  <dt className="text-muted-foreground">Time zone</dt>
                  <dd>{organization.timezone}</dd>
                </dl>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent>
                <PermissionDenied description="Viewing the organization profile requires the organization.view permission." />
              </CardContent>
            </Card>
          )}
          <Card>
            <CardHeader>
              <CardTitle>
                <h2 className="text-base">Your access</h2>
              </CardTitle>
              <CardDescription>Roles and permissions in this organization.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {organization.roles.map((role) => (
                  <Badge key={role}>{role}</Badge>
                ))}
              </div>
              <ul className="flex flex-wrap gap-1.5" aria-label="Permissions">
                {[...granted].sort().map((code) => (
                  <li key={code}>
                    <Badge variant="secondary" className="font-mono text-[0.6875rem]">
                      {code}
                    </Badge>
                  </li>
                ))}
                {granted.size === 0 ? (
                  <li className="text-muted-foreground">No permissions</li>
                ) : null}
              </ul>
            </CardContent>
          </Card>
        </div>
      ) : null}

      <PageSection
        title="Preview controls"
        description="Development only: change the fixture permissions and page state."
      >
        <Card>
          <CardContent className="grid gap-6 md:grid-cols-2">
            <fieldset className="space-y-3">
              <legend className="mb-2 font-medium">Granted permissions</legend>
              {ALL_PERMISSIONS.map((code) => {
                const id = `perm-${code}`;
                return (
                  <div key={code} className="flex items-center gap-2">
                    <Checkbox
                      id={id}
                      checked={granted.has(code)}
                      onCheckedChange={(checked) => toggle(code, checked === true)}
                    />
                    <Label htmlFor={id} className="font-mono text-xs">
                      {code}
                    </Label>
                  </div>
                );
              })}
            </fieldset>
            <fieldset className="space-y-3">
              <legend className="mb-2 font-medium">Page state</legend>
              <RadioGroup value={state} onValueChange={(value) => setState(value as PreviewState)}>
                {(["ready", "loading", "error"] as const).map((value) => (
                  <div key={value} className="flex items-center gap-2">
                    <RadioGroupItem id={`state-${value}`} value={value} />
                    <Label htmlFor={`state-${value}`} className="capitalize">
                      {value}
                    </Label>
                  </div>
                ))}
              </RadioGroup>
            </fieldset>
          </CardContent>
        </Card>
      </PageSection>
    </AppShell>
  );
}
