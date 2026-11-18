"use client";

import { KeyRound } from "lucide-react";
import { useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Input, Label, inputClass } from "@/components/ui/input";
import { cn } from "@/lib/cn";
import { CREDENTIAL_FIELDS, CREDENTIAL_LABEL, parseActionsJson } from "@/lib/connector-form";

const HTTP_EXAMPLE = `[
  {
    "name": "get_ticket",
    "description": "Read one ticket",
    "method": "GET",
    "path_template": "/tickets/{ticket_id}",
    "input_schema": {
      "type": "object", "additionalProperties": false, "required": ["ticket_id"],
      "properties": {"ticket_id": {"type": "string", "maxLength": 64}}
    },
    "side_effect": "read",
    "suggested_risk": "LOW",
    "response_fields": {"title": "internal", "status": "public"}
  }
]`;

function Field({ id, label, hint, children, invalid }: { id: string; label: string; hint?: ReactNode; children: ReactNode; invalid?: boolean }) {
  return (
    <div>
      <Label htmlFor={id}>{label}</Label>
      <div className="mt-1.5">{children}</div>
      {hint ? <p id={`${id}-hint`} className="mt-1 text-caption text-gray-11">{hint}</p> : null}
      {invalid ? <p className="mt-1 text-caption font-medium text-bad-11">The gateway rejected this field.</p> : null}
    </div>
  );
}

const selectClass = cn(inputClass, "pr-8");

/** Per-type configuration form (C2). Plain HTML form POST to a guarded route handler: the
 *  credentials go only there (password inputs, never pre-filled, gone after the redirect). */
export function ConnectorConfigForm({ typeId, csrf, action, mode, initial = {}, name = "", slug = "", errorFields = [], submitLabel, next }: {
  typeId: string; csrf: string; action: string; mode: "create" | "edit"; initial?: Record<string, unknown>;
  name?: string; slug?: string; errorFields?: string[]; submitLabel: string; next?: string;
}) {
  const [jsonError, setJsonError] = useState<string | null>(null);
  const bad = (f: string) => errorFields.some((e) => e === f || e.startsWith(`${f}.`));
  const str = (k: string) => (typeof initial[k] === "string" || typeof initial[k] === "number" ? String(initial[k]) : "");
  const arr = (k: string) => (Array.isArray(initial[k]) ? (initial[k] as unknown[]).map(String).join(", ") : "");
  const creds = mode === "create" ? CREDENTIAL_FIELDS[typeId] ?? [] : [];
  const [mailMode, setMailMode] = useState(str("mode") || "smtp");

  const text = (k: string, label: string, opts: { hint?: ReactNode; placeholder?: string; required?: boolean; value?: string; type?: string } = {}) => (
    <Field id={`f-${k}`} label={label} hint={opts.hint} invalid={bad(`config.${k}`)}>
      <Input id={`f-${k}`} name={`config.${k}`} defaultValue={opts.value ?? str(k)} placeholder={opts.placeholder} required={opts.required}
        type={opts.type ?? "text"} aria-invalid={bad(`config.${k}`) || undefined} aria-describedby={opts.hint ? `f-${k}-hint` : undefined} autoComplete="off" spellCheck={false} />
    </Field>
  );

  return (
    <form method="post" action={action} className="space-y-4" data-testid="connector-form"
      onSubmit={(e) => {
        if (typeId !== "http_api") return;
        const raw = (e.currentTarget.elements.namedItem("config.actions") as HTMLTextAreaElement | null)?.value ?? "";
        const r = parseActionsJson(raw);
        if (!r.ok) {
          e.preventDefault();
          setJsonError(r.error);
        } else setJsonError(null);
      }}>
      <input type="hidden" name="csrf" value={csrf} />
      <input type="hidden" name="type_id" value={typeId} />
      {next ? <input type="hidden" name="next" value={next} /> : null}

      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="f-name" label="Display name" invalid={bad("name")}>
          <Input id="f-name" name="name" defaultValue={name} required maxLength={120} aria-invalid={bad("name") || undefined} autoComplete="off" />
        </Field>
        {mode === "create" ? (
          <Field id="f-slug" label="Slug" hint="2–24 lowercase letters or digits, starting with a letter. Tools are named cx_<slug>_<action>." invalid={bad("slug")}>
            <Input id="f-slug" name="slug" defaultValue={slug} required pattern="[a-z][a-z0-9]{1,23}" maxLength={24} aria-invalid={bad("slug") || undefined}
              aria-describedby="f-slug-hint" autoComplete="off" spellCheck={false} className="font-mono" />
          </Field>
        ) : null}
      </div>

      {typeId === "slack" ? (
        <>
          {text("default_channel", "Default channel (optional)", { placeholder: "#approvals" })}
          <fieldset>
            <legend className="text-caption font-medium text-gray-11">Notify on</legend>
            <div className="mt-1.5 flex flex-wrap gap-4 text-dense">
              {([["approval_required", "Approval required"], ["security_violation", "Security violation"], ["connector_change", "Connector change"]] as const).map(([v, l]) => {
                const cur = Array.isArray(initial.notify_on) ? (initial.notify_on as string[]) : ["approval_required"];
                return (
                  <label key={v} className="inline-flex items-center gap-1.5">
                    <input type="checkbox" name="config.notify_on" value={v} defaultChecked={cur.includes(v)} className="size-4 accent-brand-9" />{l}
                  </label>
                );
              })}
            </div>
          </fieldset>
        </>
      ) : null}

      {typeId === "email" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="f-mode" label="Delivery mode" invalid={bad("config.mode")}>
            <select id="f-mode" name="config.mode" value={mailMode} onChange={(e) => setMailMode(e.target.value)} className={selectClass}>
              <option value="smtp">SMTP</option>
              <option value="http">HTTP API</option>
            </select>
          </Field>
          {text("from_address", "From address", { required: true, placeholder: "agentguard@example.com", type: "email" })}
          {text("allowed_domains", "Allowed recipient domains (comma separated)", { value: arr("allowed_domains"), placeholder: "example.com, partner.example" })}
          {mailMode === "smtp" ? (
            <>
              {text("smtp_host", "SMTP host", { required: true, placeholder: "smtp.example.com" })}
              {text("smtp_port", "SMTP port", { placeholder: "587" })}
              {text("smtp_username", "SMTP username (optional)")}
            </>
          ) : (
            text("http_url", "HTTP API URL", { required: true, placeholder: "https://api.mail.example/send" })
          )}
        </div>
      ) : null}

      {typeId === "http_api" ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2">
            {text("base_url", "Base URL (https)", { required: true, placeholder: "https://api.example.com/v1" })}
            {text("allowed_hosts", "Allowed hosts (exact, comma separated)", { required: true, value: arr("allowed_hosts"), placeholder: "api.example.com" })}
            {text("auth_header_name", "Auth header name", { placeholder: "Authorization" })}
            {text("health_path", "Health path (optional)", { placeholder: "/health" })}
          </div>
          <Field id="f-actions" label="Actions (JSON array)" invalid={bad("config.actions")}
            hint="Each action: name, method, path_template, input_schema (flat object of string/integer/boolean/string-array properties), side_effect, suggested_risk, response_fields. Validated here and by the gateway.">
            <textarea id="f-actions" name="config.actions" rows={12} spellCheck={false} aria-describedby="f-actions-hint"
              aria-invalid={Boolean(jsonError) || bad("config.actions") || undefined}
              defaultValue={Array.isArray(initial.actions) ? JSON.stringify(initial.actions, null, 2) : ""} placeholder={HTTP_EXAMPLE}
              className="w-full rounded-md border border-gray-7 bg-gray-1 px-2.5 py-2 font-mono text-caption text-gray-12 placeholder:text-gray-10 focus-visible:border-brand-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-7/60" />
          </Field>
          {jsonError ? <p role="alert" className="text-caption font-medium text-bad-11" data-testid="json-error">{jsonError}</p> : null}
        </>
      ) : null}

      {typeId === "mcp_upstream" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {text("url", "MCP server URL (https)", { required: true, placeholder: "https://mcp.example.com/mcp" })}
          {text("allowed_hosts", "Allowed hosts (exact, comma separated)", { required: true, value: arr("allowed_hosts"), placeholder: "mcp.example.com" })}
        </div>
      ) : null}

      {typeId === "github" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="f-owner_type" label="Install the App on" invalid={bad("config.owner_type")}>
            <select id="f-owner_type" name="config.owner_type" defaultValue={str("owner_type") || "org"} className={selectClass}>
              <option value="org">An organization</option>
              <option value="user">A personal account</option>
            </select>
          </Field>
          {text("owner", "Organization or user name", { placeholder: "acme" })}
          {text("repos", "Repositories (owner/name, comma separated)", {
            required: true, value: arr("repos"), placeholder: "acme/payments",
            hint: "The ONLY repositories AgentGuard may read or push to. Its GitHub token is limited to these.",
          })}
          <Field id="f-mode" label="How GitHub reaches AgentGuard" invalid={bad("config.mode")}
            hint="Polling needs no public URL: open pull requests are checked every 60 seconds.">
            <select id="f-mode" name="config.mode" defaultValue={str("mode") || "webhook"} className={selectClass} aria-describedby="f-mode-hint">
              <option value="webhook">Webhook (needs a public https URL)</option>
              <option value="polling">Polling (local / no public URL)</option>
            </select>
          </Field>
          {text("protected_branches", "Protected branches (never pushed to)", {
            value: arr("protected_branches") || "main, master", placeholder: "main, master",
          })}
        </div>
      ) : null}

      {creds.length ? (
        <fieldset className="rounded-md border border-gray-6 p-3">
          <legend className="px-1 text-caption font-medium text-gray-11"><KeyRound aria-hidden="true" className="mr-1 inline size-3.5" />Credentials (write-only)</legend>
          <p className="mb-3 text-caption text-gray-11">Sealed on the gateway and never shown again. {typeId === "slack" ? "Give a webhook URL, a bot token, or both." : "Leave empty what you do not use."}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            {creds.map((f) => (
              <Field key={f} id={`c-${f}`} label={CREDENTIAL_LABEL[f] ?? f} invalid={bad(`credentials.${f}`) || bad("credentials")}>
                <Input id={`c-${f}`} name={`cred.${f}`} type="password" autoComplete="new-password" spellCheck={false} className="font-mono"
                  aria-invalid={bad(`credentials.${f}`) || undefined} />
              </Field>
            ))}
          </div>
        </fieldset>
      ) : null}

      <div className="flex justify-end gap-2">
        <Button type="submit" variant="primary">{submitLabel}</Button>
      </div>
    </form>
  );
}
