import { AgentText } from "@/components/humanize/agent-text";
import type { Phrase } from "@/src/humanize";

/** "edit <code>api/src/x.ts</code>", "run <code>pnpm test</code>", "use <code>srv/tool</code> via MCP". */
export function PhraseView({ phrase }: { phrase: Phrase }) {
  // Commands: the meaning in the title; the whole command is shown where the step is opened.
  if (!phrase.object || phrase.kind === "command") return <>{phrase.text}</>;
  if (phrase.kind === "tool") return <>use <AgentText value={phrase.object} /> via MCP</>;
  if (phrase.text.endsWith(")") && phrase.text.includes(` (${phrase.object})`)) {
    return <>{phrase.verb} (<AgentText value={phrase.object} />)</>; // git: "switch branches (git checkout main)"
  }
  return <>{phrase.verb} <AgentText value={phrase.object} /></>;
}
