import "server-only";

import { gateway } from "@/lib/gateway";
import { EMPTY_BOOK, type RuleBook } from "@/src/humanize";

/** Plain-English rule descriptions from the gateway (versioned next to the policies). They are
 *  the same for every tenant and change only with a gateway release, so the dashboard server
 *  keeps them for 10 minutes instead of asking on every page (fewer calls against the
 *  per-session rate limit). A page still renders without them: rule ids are shown as they are. */
let cached: { book: RuleBook; at: number } | null = null;
const TTL_MS = 10 * 60 * 1000;

export async function ruleBook(): Promise<RuleBook> {
  if (cached && Date.now() - cached.at < TTL_MS) return cached.book;
  try {
    const { data } = await (await gateway()).GET("/v1/dashboard/rule-descriptions");
    if (!data) return cached?.book ?? EMPTY_BOOK;
    cached = { book: { rules: data.rules, patterns: data.patterns }, at: Date.now() };
    return cached.book;
  } catch {
    return cached?.book ?? EMPTY_BOOK;
  }
}
