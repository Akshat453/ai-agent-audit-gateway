import "server-only";

import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";

export type RepoChoice = { repo_id: string; name: string; sessions: number };

/** The repository the console is scoped to (ADR-0040), or null for "all repositories".
 *  A stale id (deleted repository, other tenant) falls back to all. */
export async function repoScope(): Promise<{ id: string | null; name: string | null; choices: RepoChoice[] }> {
  const [p, res] = await Promise.all([prefs(), (await gateway()).GET("/v1/dashboard/repo-choices")]);
  const choices = (res.data ?? []) as RepoChoice[];
  const hit = choices.find((c) => c.repo_id === p.repo);
  return { id: hit?.repo_id ?? null, name: hit?.name ?? null, choices };
}
