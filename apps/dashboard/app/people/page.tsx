import type { Metadata } from "next";

import { ErrorState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { InviteForm } from "@/components/people/invite-form";
import { StatusBadge } from "@/components/status-badge";
import { StepUpCard } from "@/components/step-up";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { viewer } from "@/lib/c2";
import { INVITE_ROLES, type Person } from "@/lib/connectors";


export const metadata: Metadata = { title: "People" };

export default async function People() {
  const { gw, isAdmin, csrf, stepUpRemaining, stepUpWindow } = await viewer();
  const header = <PageHeader toggle={false} title="People" help="people" crumbs={[{ label: "Setup" }, { label: "People" }]} description="The humans of this tenant and their roles. Invite approvers, auditors and admins." />;
  const res = isAdmin ? await gw.GET("/v1/people") : null;
  const people = (res?.data as { people?: Person[] } | undefined)?.people;
  if (!isAdmin || !people) {
    return (
      <div className="mx-auto max-w-5xl">
        {header}
        <ErrorState what={!isAdmin || res?.response.status === 403 ? "Only an admin can manage people." : "The gateway did not return the people list."} retryHref="/people" />
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-5xl space-y-4">
      {header}
      <Card>
        <CardHeader title="Invite a person" description="Needs a recent step-up. They sign in with the temporary password shown once." />
        <CardBody>
          <StepUpCard csrf={csrf} next="/people" remaining={stepUpRemaining} windowSeconds={stepUpWindow} what="invite people" />
          <InviteForm csrf={csrf} roles={INVITE_ROLES} />
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Members" description={`${people.length} ${people.length === 1 ? "person" : "people"}`} />
        <table className="w-full text-dense" data-testid="people">
          <caption className="sr-only">People in this tenant</caption>
          <thead className="border-b border-gray-5 bg-gray-2 text-left text-caption text-gray-11">
            <tr><th scope="col" className="px-4 py-2 font-medium">Username</th><th scope="col" className="px-4 py-2 font-medium">Roles</th><th scope="col" className="px-4 py-2 font-medium">Status</th></tr>
          </thead>
          <tbody className="divide-y divide-gray-4">
            {people.map((h) => (
              <tr key={h.username} className="h-[var(--row-h)]">
                <td className="px-4 py-2 font-mono">{h.username}</td>
                <td className="px-4 py-2"><ul className="flex flex-wrap gap-1">{h.roles.map((r) => <li key={r} className="rounded-sm border border-gray-6 bg-gray-2 px-1.5 font-mono text-caption">{r}</li>)}</ul></td>
                <td className="px-4 py-2"><StatusBadge value={h.status === "active" ? "ACTIVE" : h.status === "disabled" ? "PERSON_DISABLED" : h.status.toUpperCase()} size="sm" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
