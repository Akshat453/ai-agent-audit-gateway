"use client";

import { FolderGit2 } from "lucide-react";

import { useOptionalShell } from "@/components/shell/context";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger,
} from "@/components/ui/menu";

export type RepoChoice = { repo_id: string; name: string; sessions: number };

/** Top-bar repository switcher (ADR-0040): scopes runs, approvals, events, incidents and the
 *  overview to one repository. Remembered per user. */
export function RepoSwitcher({ choices }: { choices: RepoChoice[] }) {
  const shell = useOptionalShell();
  if (!shell || choices.length === 0) return null;
  const current = choices.find((c) => c.repo_id === shell.prefs.repo);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" data-testid="repo-switcher" aria-label={`Repository: ${current?.name ?? "all repositories"}. Change repository`}
          className="inline-flex max-w-56 items-center gap-1.5 rounded-full border border-gray-6 bg-gray-2 px-2 py-0.5 text-caption text-gray-11 hover:bg-gray-3">
          <FolderGit2 aria-hidden="true" className="size-3.5" />
          <span className="truncate font-medium text-gray-12">{current?.name ?? "All repositories"}</span>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>Show the console for</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={current?.repo_id ?? "all"} onValueChange={(v) => void shell.setPref("repo", v)}>
          <DropdownMenuRadioItem value="all">All repositories</DropdownMenuRadioItem>
          {choices.map((c) => (
            <DropdownMenuRadioItem key={c.repo_id} value={c.repo_id}>
              {c.name} <span className="ml-auto text-gray-11">{c.sessions} session{c.sessions === 1 ? "" : "s"}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** "Showing only <repo>" with a one-click way back to all repositories. */
export function RepoBanner({ name }: { name: string | null }) {
  const shell = useOptionalShell();
  if (!name || !shell) return null;
  return (
    <p className="mb-4 flex flex-wrap items-center gap-2 rounded-md border border-brand-7 bg-brand-2 px-3 py-2 text-dense text-gray-12" data-testid="repo-banner">
      <FolderGit2 aria-hidden="true" className="size-4 text-brand-11" />
      Showing only <strong>{name}</strong>.
      <button type="button" className="font-medium text-brand-11 underline" onClick={() => void shell.setPref("repo", "all")}>Show all repositories</button>
    </p>
  );
}
