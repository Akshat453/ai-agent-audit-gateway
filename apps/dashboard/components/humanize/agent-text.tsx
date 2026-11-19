import { Tooltip } from "@/components/ui/overlay";

/** A value the AGENT reported (a path, a command): escaped text in code style, labelled as
 *  agent-reported. React escapes it; it never becomes markup (ADR-0039). */
export function AgentText({ value, className }: { value: string; className?: string }) {
  return (
    <Tooltip content="Reported by the agent (shown as text, exactly as sent)">
      <code tabIndex={0} data-testid="agent-text" className={className ?? "break-all rounded-sm bg-gray-3 px-1 font-mono text-[0.92em] text-gray-12"}>
        {value}
      </code>
    </Tooltip>
  );
}
