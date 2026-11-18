"use client";

import { TriangleAlert, UserPlus } from "lucide-react";
import { useState } from "react";

import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

const ROLE_HELP: Record<string, string> = {
  approver: "decides approvals",
  admin: "configures the tenant",
  auditor: "investigates evidence",
  security: "security investigations and routed approvals",
  ledger_lead: "routed coding approvals (ledger)",
  maintainer: "routed coding approvals (repositories)",
};

type Invited = { username: string; roles: string[]; temporary_password: string };

/** Invite a person (C2). Sent with fetch to the guarded route handler, which answers JSON: the
 *  temporary password lives only in this component's memory and is shown ONCE (it is never in
 *  a URL, the HTML the server rendered, or browser storage). */
export function InviteForm({ csrf, roles }: { csrf: string; roles: readonly string[] }) {
  const [invited, setInvited] = useState<Invited | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (invited) {
    return (
      <div className="space-y-3" data-testid="invited">
        <div role="status" className="flex gap-2.5 rounded-md border border-warn-7 bg-warn-3 px-3.5 py-2.5 text-dense text-warn-12">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-warn-11" />
          <div>
            <p className="font-medium">{invited.username} was added ({invited.roles.join(", ")}). Copy the temporary password now: it is shown only once.</p>
            <p className="mt-0.5">Hand it over out of band (not in a ticket or chat log). Leaving or reloading this page hides it for good.</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <code className="rounded-md border border-gray-6 bg-gray-2 px-3 py-1.5 font-mono text-dense" data-testid="temporary-password">{invited.temporary_password}</code>
          <CopyButton value={invited.temporary_password} label="Copy temporary password" />
        </div>
        <Button onClick={() => { setInvited(null); window.location.reload(); }}>Done, hide it</Button>
      </div>
    );
  }

  return (
    <form className="space-y-4" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true);
      setError(null);
      try {
        const form = new FormData(e.currentTarget);
        form.set("csrf", csrf);
        const r = await fetch("/api/people", { method: "POST", body: form, credentials: "same-origin" });
        const d = (await r.json()) as Partial<Invited> & { error?: string; fields?: string[] };
        if (r.status === 201 && d.temporary_password) setInvited(d as Invited);
        else setError(
          d.error === "STEP_UP_REQUIRED" ? "Re-enter your password (step-up) above first. Nobody was added."
            : d.error === "CONFLICT" ? "That username already exists in this tenant."
              : d.error === "REQUEST_INVALID" ? `Check ${(d.fields ?? []).join(", ") || "the fields"}: lowercase username, at least one role.`
                : `The gateway answered ${d.error ?? r.status}. Nobody was added.`);
      } catch {
        setError("The request failed. Nobody was added.");
      } finally {
        setBusy(false);
      }
    }}>
      <div className="max-w-sm">
        <Label htmlFor="invite-username">Username</Label>
        <Input id="invite-username" name="username" required pattern="[a-z0-9][a-z0-9._\-]{0,63}" maxLength={64} autoComplete="off" spellCheck={false} className="mt-1.5" aria-describedby="invite-username-hint" />
        <p id="invite-username-hint" className="mt-1 text-caption text-gray-11">Lowercase letters, digits, dot, dash or underscore.</p>
      </div>
      <fieldset>
        <legend className="text-caption font-medium text-gray-11">Roles</legend>
        <div className="mt-1.5 grid gap-2 sm:grid-cols-2">
          {roles.map((r) => (
            <label key={r} className="flex items-start gap-2 text-dense">
              <input type="checkbox" name="roles" value={r} className="mt-0.5 size-4 accent-brand-9" defaultChecked={r === "approver"} />
              <span><span className="font-mono">{r}</span> <span className="text-gray-11">· {ROLE_HELP[r] ?? ""}</span></span>
            </label>
          ))}
        </div>
      </fieldset>
      {error ? <p role="alert" className="text-caption font-medium text-bad-11">{error}</p> : null}
      <Button type="submit" variant="primary" disabled={busy}><UserPlus />Invite</Button>
    </form>
  );
}
