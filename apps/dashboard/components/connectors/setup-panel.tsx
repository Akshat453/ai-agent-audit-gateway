import { CopyButton } from "@/components/copy-button";
import { StatusBadge } from "@/components/status-badge";
import { tierKey, type Setup } from "@/lib/connectors";

/** Coding-agent setup (C2): enforcement tier, the exact CLI commands, the MCP URL and the
 *  device-enrollment page developers approve their `agw login` code on. */
export function SetupPanel({ setup, enrollUrl }: { setup: Setup; enrollUrl: string }) {
  const tier = tierKey(setup.tier);
  const commands = (setup.commands ?? []).join("\n");
  return (
    <div className="space-y-4 text-dense" data-testid="setup-panel">
      {tier ? (
        <div>
          <h3 className="mb-1 text-caption font-medium text-gray-11">Enforcement tier</h3>
          <div className="flex flex-wrap items-center gap-2"><StatusBadge value={tier} /><span className="text-gray-11">{setup.tier_reason}</span></div>
        </div>
      ) : null}
      {commands ? (
        <div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <h3 className="text-caption font-medium text-gray-11">On each developer machine</h3>
            <CopyButton value={commands} label="Copy setup commands" />
          </div>
          <pre tabIndex={0} aria-label="setup commands" className="overflow-auto whitespace-pre rounded-md border border-gray-6 bg-gray-2 p-3 font-mono text-caption text-gray-12">{commands}</pre>
          <p className="mt-1 text-caption text-gray-11"><code className="font-mono">agw login</code> prints a code; the developer approves it on the enrollment page below and becomes the developer of that device.</p>
        </div>
      ) : null}
      <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-[10rem_1fr]">
        {setup.mcp_url ? (<><dt className="text-gray-11">MCP URL</dt><dd className="flex items-center gap-2"><code className="break-all font-mono">{setup.mcp_url}</code><CopyButton value={setup.mcp_url} label="Copy MCP URL" /></dd></>) : null}
        <dt className="text-gray-11">Device enrollment</dt>
        <dd><a href="/enroll" className="break-all font-mono">{enrollUrl}</a></dd>
        {setup.hook_kind ? (<><dt className="text-gray-11">Hook adapter</dt><dd className="font-mono">{setup.hook_kind}</dd></>) : null}
      </dl>
    </div>
  );
}
