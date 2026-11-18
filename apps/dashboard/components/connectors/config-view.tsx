import { KeyRound } from "lucide-react";

import { CodeView } from "@/components/code-view";
import { CREDENTIAL_LABEL } from "@/lib/connector-form";
import { EMPTY } from "@/lib/format";

/** Non-secret configuration as key/value rows, and the credential FIELDS only: which exist,
 *  whether they are set and their version. Values are write-only and never reach the browser. */
export function ConfigView({ config, credentials }: {
  config: Record<string, unknown>; credentials?: { fields: string[]; set: boolean; version: number };
}) {
  const entries = Object.entries(config);
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-dense sm:grid-cols-[12rem_1fr]" data-testid="config-view">
      {entries.length === 0 ? <><dt className="text-gray-11">Configuration</dt><dd className="text-gray-11">none</dd></> : null}
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-caption text-gray-11">{k}</dt>
          <dd className="min-w-0 break-words">
            {v === null || v === undefined || v === "" ? <span className="text-gray-11">{EMPTY}</span>
              : typeof v === "object" ? (Array.isArray(v) && v.every((x) => typeof x !== "object")
                ? (v.length ? <span className="font-mono">{v.join(", ")}</span> : <span className="text-gray-11">none</span>)
                : <CodeView text={JSON.stringify(v, null, 2)} max={4000} label={`configuration ${k}`} />)
                : <span className="font-mono">{String(v)}</span>}
          </dd>
        </div>
      ))}
      {credentials && credentials.fields.length ? (
        <div className="contents">
          <dt className="text-gray-11"><KeyRound aria-hidden="true" className="mr-1 inline size-3.5" />Credentials</dt>
          <dd data-testid="credentials-view">
            {credentials.set ? (
              <ul className="space-y-0.5">
                {credentials.fields.map((f) => (
                  <li key={f}><span className="text-gray-11">{CREDENTIAL_LABEL[f] ?? f}:</span> <span aria-hidden="true" className="font-mono">••••••••</span><span className="sr-only">set, hidden</span></li>
                ))}
                <li className="text-caption text-gray-11">Sealed, write-only · version {credentials.version}</li>
              </ul>
            ) : <span className="text-gray-11">not set</span>}
          </dd>
        </div>
      ) : null}
    </dl>
  );
}
