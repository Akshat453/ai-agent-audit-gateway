import { cn } from "@/lib/cn";

/** Read-only JSON view of UNTRUSTED text with light syntax highlighting. Every token is a React
 *  text node (escaped): highlighting only wraps substrings in <span>s, it never parses markup.
 *  Size-limited with the explicit TRUNCATED marker (ADR-0031 §2). */
const TOKEN = /("(?:\\.|[^"\\])*"(?=\s*:))|("(?:\\.|[^"\\])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\btrue\b|\bfalse\b|\bnull\b)|([{}[\],:])/g;

function highlight(text: string) {
  const out: React.ReactNode[] = [];
  let last = 0;
  let i = 0;
  for (const m of text.matchAll(TOKEN)) {
    const at = m.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    const cls = m[1] ? "text-brand-11" : m[2] ? "text-ok-11" : m[3] ? "text-high-12" : m[4] ? "text-info-11" : "text-gray-11";
    out.push(<span key={i++} className={cls}>{m[0]}</span>);
    last = at + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function CodeView({ text, max = 4000, label, className }: { text: string; max?: number; label: string; className?: string }) {
  const truncated = text.length > max;
  const shown = truncated ? text.slice(0, max) : text;
  return (
    <div className={className}>
      <pre tabIndex={0} aria-label={label} data-testid="safe-text"
        className={cn("max-h-[28rem] overflow-auto whitespace-pre-wrap break-all rounded-md border border-gray-6 bg-gray-1 p-3 font-mono text-caption leading-5 text-gray-12")}>
        {highlight(shown)}
      </pre>
      {truncated ? (
        <p className="mt-1.5 text-caption font-semibold text-warn-12" data-testid="truncated">
          [TRUNCATED: showing {max} of {text.length} characters; {text.length - max} not shown]
        </p>
      ) : null}
    </div>
  );
}
