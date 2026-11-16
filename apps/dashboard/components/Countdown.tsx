"use client";

import { useEffect, useState } from "react";

/** Live expiry countdown for an approval. Server-rendered value first (no JS needed to read
 *  it); the gateway enforces expiry by its own clock regardless of what this shows. */
export function Countdown({ expiresAt, initialSeconds }: { expiresAt: string; initialSeconds: number }) {
  const [left, setLeft] = useState(initialSeconds);
  useEffect(() => {
    const end = Date.parse(expiresAt);
    const id = setInterval(() => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000))), 1000);
    return () => clearInterval(id);
  }, [expiresAt]);
  if (left <= 0) {
    return <span className="font-bold text-red-800" data-testid="countdown">EXPIRED</span>;
  }
  const m = Math.floor(left / 60);
  const s = String(left % 60).padStart(2, "0");
  return (
    <span className="font-mono font-bold" data-testid="countdown" aria-live="polite">
      expires in {m}:{s}
    </span>
  );
}
