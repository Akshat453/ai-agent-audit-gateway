import { ArrowUpRight, CircleCheck, CircleX, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardBody } from "@/components/ui/card";
import { Term } from "@/components/humanize/term";
import { cn } from "@/lib/cn";
import type { Link } from "@/src/humanize";

/** The plain-English block every detail page opens with (ADR-0039 §5): a headline, then
 *  "What happened", "Why", "Who" and "What you can do". */
export function PlainStory({ headline, tone = "neutral", happened, why, who, canDo, children, testId = "plain-story" }: {
  headline: ReactNode; tone?: "ok" | "bad" | "warn" | "neutral";
  happened?: ReactNode[]; why?: ReactNode[]; who?: [string, ReactNode][]; canDo?: (Link | { label: string })[]; children?: ReactNode; testId?: string;
}) {
  const Icon = tone === "ok" ? CircleCheck : tone === "bad" ? CircleX : tone === "warn" ? TriangleAlert : null;
  return (
    <Card className="mb-4" data-testid={testId}>
      <CardBody className="space-y-4">
        <p className="flex items-start gap-2 text-section font-semibold text-gray-12" data-testid="plain-headline">
          {Icon ? <Icon aria-hidden="true" className={cn("mt-1 size-5 shrink-0", tone === "ok" ? "text-ok-11" : tone === "bad" ? "text-bad-11" : "text-warn-11")} /> : null}
          <span>{headline}</span>
        </p>
        <div className="grid gap-4 text-dense md:grid-cols-2">
          {happened?.length ? <Section title="What happened"><ul className="list-disc space-y-1 pl-5">{happened.map((h, i) => <li key={i}>{h}</li>)}</ul></Section> : null}
          {why?.length ? <Section title="Why"><ul className="list-disc space-y-1 pl-5">{why.map((h, i) => <li key={i}>{h}</li>)}</ul></Section> : null}
          {who?.length ? (
            <Section title="Who">
              <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1">{who.map(([k, v]) => <div key={k} className="contents"><dt className="text-gray-11">{k}</dt><dd>{v}</dd></div>)}</dl>
            </Section>
          ) : null}
          {canDo?.length ? (
            <Section title="What you can do">
              <ul className="space-y-1" data-testid="can-do">
                {canDo.map((c) => (
                  <li key={c.label}>
                    {"href" in c ? (
                      <a href={c.href} {...(c.external ? { target: "_blank", rel: "noreferrer noopener" } : {})} className="inline-flex items-center gap-1">
                        {c.label}{c.external ? <ArrowUpRight aria-hidden="true" className="size-3.5" /> : null}
                      </a>
                    ) : <span>{c.label}</span>}
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}
        </div>
        {children}
      </CardBody>
    </Card>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title}>
      <h2 className="mb-1.5 text-caption font-semibold uppercase tracking-wide text-gray-11">{title}</h2>
      <div className="text-gray-12">{children}</div>
    </section>
  );
}

/** One plain sentence on top of a page (Technical view keeps only this line). */
export function PlainLine({ children, testId = "plain-headline" }: { children: ReactNode; testId?: string }) {
  return <p className="mb-4 rounded-md border border-gray-6 bg-gray-2 px-4 py-3 text-body text-gray-12" data-testid={testId}>{children}</p>;
}

/** "Is this record intact?" in words. */
export function IntactBadge({ intact }: { intact: { tone: "ok" | "warn" | "bad"; text: string } }) {
  const Icon = intact.tone === "ok" ? CircleCheck : intact.tone === "bad" ? CircleX : TriangleAlert;
  return (
    <div className={cn("flex items-start gap-2 rounded-md border px-3 py-2 text-dense",
      intact.tone === "ok" ? "border-ok-7 bg-ok-2" : intact.tone === "bad" ? "border-bad-7 bg-bad-2" : "border-warn-7 bg-warn-2")} data-testid="intact">
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", intact.tone === "ok" ? "text-ok-11" : intact.tone === "bad" ? "text-bad-11" : "text-warn-11")} />
      <span><span className="font-medium">Is this record <Term term="evidence">intact</Term>?</span> {intact.text}</span>
    </div>
  );
}

/** A plain stepper (Asked -> Checked -> Cleared -> Started -> outcome). */
export function PlainSteps({ steps, label = "What happened, step by step" }: {
  steps: { key: string; label: string; done: boolean; tone: "ok" | "bad" | "warn" | "todo"; note?: string; at?: ReactNode }[]; label?: string;
}) {
  return (
    <ol aria-label={label} className="flex flex-wrap gap-y-3" data-testid="plain-steps">
      {steps.map((s, i) => (
        <li key={s.key} className="flex min-w-28 flex-1 items-start">
          <div className="flex w-full flex-col">
            <div className="flex items-center">
              <span aria-hidden="true" className={cn("size-3 shrink-0 rounded-full border-2",
                s.tone === "ok" ? "border-ok-9 bg-ok-9" : s.tone === "bad" ? "border-bad-9 bg-bad-9" : s.tone === "warn" ? "border-warn-9 bg-warn-9" : "border-gray-7 bg-gray-1")} />
              {i < steps.length - 1 ? <span aria-hidden="true" className={cn("mx-2 h-0.5 flex-1 rounded-full", s.done && steps[i + 1]?.done && s.tone !== "todo" && steps[i + 1]?.tone !== "todo" ? "bg-ok-9" : "bg-gray-5")} /> : null}
            </div>
            <span className={cn("mt-1 text-dense font-medium", s.done ? "text-gray-12" : "text-gray-11")}>{s.label}</span>
            <span className="text-caption text-gray-11">{s.done ? s.at ?? null : s.note ?? "not reached"}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}
