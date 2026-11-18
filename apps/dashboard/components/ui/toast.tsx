"use client";

import * as ToastPrimitive from "@radix-ui/react-toast";
import { CheckCircle2, CircleAlert, Info, X } from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "@/lib/cn";

/** Toasts on Radix Toast (sonner was rejected: it injects an un-nonced <style> tag, which the
 *  strict CSP blocks; ADR-0033 §2). A tiny module-level queue so any client component can call
 *  toast(); Toaster renders them in a polite live region. */
type Tone = "ok" | "bad" | "info";
type Item = { id: number; title: string; description?: string; tone: Tone };
let next = 1;
const listeners = new Set<(t: Item) => void>();

export function toast(title: string, opts: { description?: string; tone?: Tone } = {}) {
  const item = { id: next++, title, description: opts.description, tone: opts.tone ?? "info" };
  listeners.forEach((l) => l(item));
}

const ICON = { ok: CheckCircle2, bad: CircleAlert, info: Info };
const TONE = { ok: "text-ok-11", bad: "text-bad-11", info: "text-brand-11" };

export function Toaster() {
  const [items, setItems] = useState<Item[]>([]);
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
    const on = (t: Item) => setItems((xs) => [...xs.slice(-3), t]);
    listeners.add(on);
    return () => void listeners.delete(on);
  }, []);
  // Radix renders the viewport's region wrapper with style="pointer-events:none"; server-
  // rendered, that attribute is blocked by the strict CSP. Mounting client-side applies it
  // through the CSSOM instead.
  if (!mounted) return null;
  return (
    <ToastPrimitive.Provider swipeDirection="right" duration={5000}>
      {items.map((t) => {
        const Icon = ICON[t.tone];
        return (
          <ToastPrimitive.Root key={t.id} onOpenChange={(o) => !o && setItems((xs) => xs.filter((x) => x.id !== t.id))}
            className="flex w-full items-start gap-3 rounded-md border border-gray-6 bg-gray-1 p-3 shadow-xl data-[state=open]:animate-slide">
            <Icon className={cn("mt-0.5 size-4 shrink-0", TONE[t.tone])} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <ToastPrimitive.Title className="text-dense font-medium">{t.title}</ToastPrimitive.Title>
              {t.description ? <ToastPrimitive.Description className="mt-0.5 text-caption text-gray-11">{t.description}</ToastPrimitive.Description> : null}
            </div>
            <ToastPrimitive.Close aria-label="Dismiss" className="rounded-sm p-0.5 text-gray-11 hover:bg-gray-4"><X className="size-3.5" /></ToastPrimitive.Close>
          </ToastPrimitive.Root>
        );
      })}
      <ToastPrimitive.Viewport className="fixed bottom-4 right-4 z-[60] flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2 outline-none" />
    </ToastPrimitive.Provider>
  );
}

/** Fire one toast on mount (server-rendered flash after a form POST redirect). */
export function FlashToast({ title, description, tone }: { title: string; description?: string; tone?: Tone }) {
  useEffect(() => {
    const id = setTimeout(() => toast(title, { description, tone }), 50);
    return () => clearTimeout(id);
  }, [title, description, tone]);
  return null;
}
