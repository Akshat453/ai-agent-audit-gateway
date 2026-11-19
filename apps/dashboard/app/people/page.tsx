import type { Metadata } from "next";

import { ErrorState } from "@/components/empty-state";
import { PlainLine } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { PageHeader } from "@/components/page-header";
import { InviteForm } from "@/components/people/invite-form";
import { StatusBadge } from "@/components/status-badge";
import { StepUpCard } from "@/components/step-up";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { viewer } from "@/lib/c2";
import { INVITE_ROLES, type Person } from "@/lib/connectors";
import { prefs } from "@/lib/prefs";
import { plainStatus, roleWords } from "@/src/humanize";

export const metadata: Metadata = { title: "People" };

export default async function People() {
  const { gw, isAdmin, csrf, stepUpRemaining, stepUpWindow } = await viewer();
  const header = <PageHeader title="People" help="people" crumbs={[{ label: "Setup" }, { label: "People" }]} description="The humans of this tenant and their roles. Invite approvers, auditors and admins." />;
  const [res, p] = await Promise.all([isAdmin ? gw.GET("/v1/people") : Promise.resolve(null), prefs()]);
  const people = (res?.data as { people?: Person[] } | undefined)?.people;
  if (!isAdmin || !people) {
    return (
      <div className="mx-auto max-w-5xl">
        {header}
        <ErrorState what={!isAdmin || res?.response.status === 403 ? "Only an admin can see and invite people. Ask an admin if you need a role changed." : "AgentGuard could not load the people list. Try again in a moment."} retryHref="/people" />
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
      <PlainLine>{people.length} {people.length === 1 ? "person has" : "people have"} access. Agents never appear here: this list is only the humans who approve, review and configure.</PlainLine>
      {p.view === "simple" ? (
        <ul className="divide-y divide-gray-4 rounded-md border border-gray-6 bg-gray-1 text-dense" aria-label="People in plain English" data-testid="people-sentences">
          {people.map((h) => <li key={h.username} className="px-4 py-2"><span className="font-medium">{h.username}</span>: {roleWords(h.roles)}. <span className="text-gray-11">{plainStatus(h.status === "active" ? "ACTIVE" : "PERSON_DISABLED")}.</span></li>)}
        </ul>
      ) : null}
      <Technical view={p.view}>
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
      </Technical>
    </div>
  );
}
