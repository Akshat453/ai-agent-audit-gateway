"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/overlay";
import { cn } from "@/lib/cn";
import { EMPTY, middle } from "@/lib/format";

/** Middle-truncated mono hash/id: click shows the full value (popover), the copy button copies
 *  it, `href` makes the id a link to its entity (§3.5: no dead ends). */
export function HashChip({ value, href, label, head = 6, tail = 4, className, testId }: {
  value: string | null | undefined; href?: string; label?: string; head?: number; tail?: number; className?: string; testId?: string;
}) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-gray-11">{EMPTY}</span>;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard blocked: the popover still shows the full value */
    }
  };
  const short = middle(value, head, tail);
  return (
    <span className={cn("group inline-flex max-w-full items-center gap-0.5 align-middle", className)} data-testid={testId}>
      {href ? (
        <a href={href} className="truncate font-mono text-dense text-brand-11" title={value} aria-label={`${label ?? "id"} ${value}`}>
          {short}
        </a>
      ) : (
        <Popover>
          <PopoverTrigger className="cursor-pointer truncate rounded-sm font-mono text-dense text-gray-12 hover:bg-gray-3" aria-label={`${label ?? "hash"} ${value}: show full value`}>
            {short}
          </PopoverTrigger>
          <PopoverContent className="max-w-[min(90vw,40rem)]">
            {label ? <div className="mb-1 text-caption font-medium text-gray-11">{label}</div> : null}
            <code className="block break-all font-mono text-caption text-gray-12">{value}</code>
          </PopoverContent>
        </Popover>
      )}
      <button
        type="button"
        onClick={copy}
        aria-label={`Copy ${label ?? "value"}`}
        className="rounded-sm p-0.5 text-gray-11 opacity-0 transition-opacity hover:bg-gray-4 hover:text-gray-12 focus-visible:opacity-100 group-hover:opacity-100"
      >
        {copied ? <Check className="size-3.5 text-ok-11" /> : <Copy className="size-3.5" />}
      </button>
    </span>
  );
}
