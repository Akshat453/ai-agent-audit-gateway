import {
  Ban, FileEdit, FileSearch, FileText, FileX, FolderGit2, GitPullRequest, Globe, Search, ShieldAlert, SquareTerminal, Wrench,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/cn";
import { clock, storyCounts, type StepKind, type StoryLine } from "@/src/humanize";

const ICON: Record<StepKind, LucideIcon> = {
  command: SquareTerminal, git: FolderGit2, edit: FileEdit, read: FileText, delete: FileX, search: Search,
  web: Globe, tool: Wrench, github: GitPullRequest, security: ShieldAlert, other: FileSearch,
};
const PILL = {
  ok: "border-ok-7 bg-ok-3 text-ok-12", bad: "border-bad-7 bg-bad-3 text-bad-12",
  warn: "border-warn-7 bg-warn-3 text-warn-12", info: "border-info-7 bg-info-3 text-info-12",
} as const;

export const STORY_FILTERS = [
  ["all", "All"], ["blocked", "Blocked"], ["person", "Needed a person"], ["commands", "Commands"], ["files", "Files"], ["github", "GitHub"],
] as const;
export type StoryFilter = (typeof STORY_FILTERS)[number][0];

function keep(l: StoryLine, f: StoryFilter): boolean {
  switch (f) {
    case "blocked": return l.outcome.tone === "bad";
    case "person": return l.approval.length > 0;
    case "commands": return l.kind === "command" || l.kind === "git";
    case "files": return ["edit", "read", "delete", "search"].includes(l.kind);
    case "github": return l.kind === "github";
    default: return true;
  }
}

/** The session story as a structured list (ADR-0042 follow-up): one row per step with a fixed
 *  time column, the kind of step, the exact command / file (escaped, one line, full text on
 *  click), one outcome badge, and why a person or a block was involved. */
/** "Approved by akshat 2 min later", "Waiting for a person to approve", "Rejected by akshat". */
function person(l: StoryLine): string | null {
  const decided = l.approval.filter((a) => a !== "needed approval");
  if (decided.length) return decided.map((a) => a.charAt(0).toUpperCase() + a.slice(1)).join(" · ");
  if (l.approval.length) return l.outcome.text.startsWith("Expired") ? "Nobody approved it in time" : "Waiting for a person to approve";
  return null;
}

export function RunStory({ lines, tz, filter, baseHref }: { lines: StoryLine[]; tz: "local" | "utc"; filter: StoryFilter; baseHref: string }) {
  const shown = lines.filter((l) => keep(l, filter));
  return (
    <section aria-label="Session story" data-testid="run-story">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-dense text-gray-11" data-testid="story-counts">{storyCounts(lines)}.</p>
        <nav aria-label="Show steps" className="flex flex-wrap gap-1.5">
          {STORY_FILTERS.map(([k, label]) => (
            <a key={k} href={k === "all" ? baseHref : `${baseHref}?show=${k}`} aria-current={k === filter ? "true" : undefined}
              className={cn("rounded-full border px-2.5 py-0.5 text-caption font-medium no-underline hover:no-underline",
                k === filter ? "border-brand-8 bg-brand-3 text-brand-12" : "border-gray-7 text-gray-11 hover:bg-gray-3 hover:text-gray-12")}>
              {label}
            </a>
          ))}
        </nav>
      </div>
      {shown.length === 0 ? <p className="rounded-md border border-gray-6 px-4 py-6 text-center text-dense text-gray-11">No steps of this kind in this session.</p> : (
        <ol className="divide-y divide-gray-5 overflow-hidden rounded-md border border-gray-6" data-testid="story-rows">
          {shown.map((l, i) => {
            const Icon = ICON[l.kind];
            const row = (
              <div className="grid grid-cols-[4.5rem_1.25rem_minmax(0,1fr)_auto] items-start gap-x-3 px-3 py-2.5 sm:grid-cols-[5.5rem_1.25rem_6.5rem_minmax(0,1fr)_auto]">
                <span className="pt-0.5 text-caption tabular text-gray-11">{clock(l.at, tz)}</span>
                <Icon aria-hidden="true" className={cn("mt-0.5 size-4", l.kind === "security" ? "text-warn-11" : "text-gray-11")} />
                {l.actionId
                  ? <a href={`/actions/${l.actionId}`} className="hidden pt-0.5 text-caption font-medium sm:block" title="Open this step">{l.label}</a>
                  : <span className="hidden pt-0.5 text-caption font-medium text-gray-11 sm:block">{l.label}</span>}
                <div className="min-w-0">
                  {l.object && (l.kind === "command" || l.kind === "git") ? (
                    <details>
                      <summary className="cursor-pointer text-dense text-gray-12 marker:text-gray-9" data-testid="story-summary">{l.text}</summary>
                      <code data-testid="agent-text" className="mt-1 block whitespace-pre-wrap break-all rounded-sm bg-gray-3 px-1.5 py-1 font-mono text-caption text-gray-12">{l.object}</code>
                    </details>
                  ) : l.object ? (
                    <code data-testid="agent-text" className="block truncate rounded-sm bg-gray-3 px-1.5 py-0.5 font-mono text-caption text-gray-12" title={l.object}>{l.object}</code>
                  ) : <span className="text-dense text-gray-12">{l.text}</span>}
                  {person(l) ? <p className="mt-1 text-caption text-gray-11" data-testid="story-person">{person(l)}</p> : null}
                  {l.why ? <p className="mt-0.5 text-caption text-gray-11" data-testid="story-why">Why: {l.why}</p> : null}
                </div>
                <span className={cn("mt-0.5 inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[11px] font-medium", PILL[l.outcome.tone])}>
                  {l.outcome.tone === "bad" ? <Ban aria-hidden="true" className="size-3" /> : null}{l.outcome.text}
                </span>
              </div>
            );
            return (
              <li key={`${l.actionId ?? "e"}-${i}`} className={cn("bg-gray-1 hover:bg-gray-2", l.kind === "security" && "bg-warn-2")}>
                {row}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
