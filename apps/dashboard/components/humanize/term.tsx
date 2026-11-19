import type { ReactNode } from "react";

import { Tooltip } from "@/components/ui/overlay";
import { meaning } from "@/src/humanize";

/** A technical word with its one-line meaning on hover/focus (dotted underline). */
export function Term({ term, children }: { term: string; children?: ReactNode }) {
  const m = meaning(term);
  if (!m) return <>{children ?? term}</>;
  return (
    <Tooltip content={m}>
      <span tabIndex={0} data-term={term} className="cursor-help underline decoration-gray-8 decoration-dotted underline-offset-4">{children ?? term}</span>
    </Tooltip>
  );
}
