"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";

/** Copies a value to the clipboard (setup commands, a one-time temporary password). */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" variant="secondary" aria-label={label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked: the value is visible to select by hand */
        }
      }}>
      {copied ? <Check /> : <Copy />}{copied ? "Copied" : "Copy"}
    </Button>
  );
}
