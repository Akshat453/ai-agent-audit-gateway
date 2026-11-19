/** The WHOLE agent-reported command (or URL / query) where a step is opened (ADR-0043):
 *  titles show its meaning; this block shows exactly what the agent asked to run. */
export function FullTarget({ value, kind }: { value: string | null; kind: string | null }) {
  if (!value || (kind !== "command" && kind !== "url" && kind !== "query")) return null;
  const label = kind === "command" ? "The exact command" : kind === "url" ? "The exact address" : "The exact search";
  return (
    <section aria-label={label} className="space-y-1" data-testid="full-target">
      <h2 className="text-caption font-semibold uppercase tracking-wide text-gray-11">{label} <span className="font-normal normal-case tracking-normal">(as reported by the agent; secrets are replaced by [REDACTED])</span></h2>
      <pre tabIndex={0} className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-gray-6 bg-gray-2 p-3 font-mono text-caption text-gray-12">{value}</pre>
    </section>
  );
}
