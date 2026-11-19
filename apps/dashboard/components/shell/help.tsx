"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { CircleHelp, X } from "lucide-react";

import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { useOptionalShell, useShell } from "@/components/shell/context";
import { HELP } from "@/lib/help";
import { ALL_RISKS, riskMeta, statusMeta } from "@/lib/status";
import { meaning } from "@/src/humanize";

/** The "?" next to a page title: opens the help drawer for that page (§4). */
export function HelpButton({ topic }: { topic: string }) {
  const shell = useOptionalShell();
  if (!shell) return null;
  return (
    <button type="button" onClick={() => shell.openHelp(topic)} aria-label="Help for this page"
      className="rounded-full p-1 text-gray-11 transition-colors hover:bg-gray-4 hover:text-gray-12">
      <CircleHelp className="size-4" />
    </button>
  );
}

/** Right-side drawer: plain-language explanation of the page and each of its statuses. */
export function HelpDrawer() {
  const { help, closeHelp } = useShell();
  const topic = help ? HELP[help] ?? HELP.default : null;
  return (
    <DialogPrimitive.Root open={help !== null} onOpenChange={(o) => !o && closeHelp()}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/20" />
        <DialogPrimitive.Content className="fixed inset-y-0 right-0 z-50 flex w-[400px] max-w-[92vw] flex-col border-l border-gray-6 bg-gray-1 shadow-2xl outline-none data-[state=open]:animate-slide">
          <div className="flex items-center justify-between border-b border-gray-5 px-5 py-4">
            <DialogPrimitive.Title className="text-section font-semibold">Help · {topic?.title}</DialogPrimitive.Title>
            <DialogPrimitive.Close aria-label="Close help" className="rounded-sm p-1 text-gray-11 hover:bg-gray-4"><X className="size-4" /></DialogPrimitive.Close>
          </div>
          {topic ? (
            <div className="space-y-5 overflow-y-auto px-5 py-4 text-dense">
              <DialogPrimitive.Description className="text-body text-gray-12">{topic.summary}</DialogPrimitive.Description>
              <ul className="list-disc space-y-1.5 pl-4 text-gray-11">{topic.points.map((p) => <li key={p}>{p}</li>)}</ul>
              {topic.statuses?.length ? (
                <section>
                  <h3 className="mb-2 text-caption font-medium uppercase tracking-wide text-gray-11">Statuses on this page</h3>
                  <dl className="space-y-3">
                    {topic.statuses.map((s) => (
                      <div key={s}>
                        <dt><StatusBadge value={s} /></dt>
                        <dd className="mt-1 text-gray-11">{statusMeta(s).help}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
              ) : null}
              {topic.terms?.length ? (
                <section>
                  <h3 className="mb-2 text-caption font-medium uppercase tracking-wide text-gray-11">Words on this page</h3>
                  <dl className="space-y-2" data-testid="help-terms">
                    {topic.terms.map((t) => <div key={t}><dt className="font-medium text-gray-12">{t}</dt><dd className="text-gray-11">{meaning(t)}</dd></div>)}
                  </dl>
                </section>
              ) : null}
              {topic.risks ? (
                <section>
                  <h3 className="mb-2 text-caption font-medium uppercase tracking-wide text-gray-11">Risk levels</h3>
                  <dl className="space-y-3">
                    {ALL_RISKS.map((r) => (
                      <div key={r}><dt><RiskBadge level={r} /></dt><dd className="mt-1 text-gray-11">{riskMeta(r).help}</dd></div>
                    ))}
                  </dl>
                </section>
              ) : null}
              <p className="rounded-md border border-gray-6 bg-gray-2 p-3 text-caption text-gray-11">
                This console is a convenience view. Independent verification uses the CLI (<code className="font-mono">agw-verify</code>) with trust roots you obtained out of band.
              </p>
            </div>
          ) : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
