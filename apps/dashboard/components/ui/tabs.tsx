"use client";

import { createContext, useContext, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { cn } from "@/lib/cn";

/**
 * WAI-ARIA tabs (tablist / tab / tabpanel, roving tabindex, Arrow/Home/End keys). Our own small
 * component instead of @radix-ui/react-tabs: Radix server-renders inactive panels with
 * style="animation-duration:0s", an inline style attribute the strict CSP blocks (ADR-0033 §2).
 * Same API shape as the shadcn/ui Tabs.
 */
type Ctx = { value: string; setValue: (v: string) => void; base: string };
const TabsCtx = createContext<Ctx | null>(null);
const use = () => {
  const c = useContext(TabsCtx);
  if (!c) throw new Error("Tabs parts must be inside <Tabs>");
  return c;
};

export function Tabs({ defaultValue, children, className }: { defaultValue: string; children: ReactNode; className?: string }) {
  const [value, setValue] = useState(defaultValue);
  const base = useId();
  return <TabsCtx.Provider value={{ value, setValue, base }}><div className={className}>{children}</div></TabsCtx.Provider>;
}

export function TabsList({ children, className, "aria-label": label }: { children: ReactNode; className?: string; "aria-label"?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const onKey = (e: KeyboardEvent) => {
    const tabs = Array.from(ref.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]') ?? []);
    const i = tabs.findIndex((t) => t === document.activeElement);
    if (i < 0) return;
    const to = e.key === "ArrowRight" ? (i + 1) % tabs.length : e.key === "ArrowLeft" ? (i - 1 + tabs.length) % tabs.length
      : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    tabs[to]?.focus();
    tabs[to]?.click();
  };
  return (
    <div ref={ref} role="tablist" aria-label={label} onKeyDown={onKey} className={cn("flex gap-1 border-b border-gray-6", className)}>
      {children}
    </div>
  );
}

export function TabsTrigger({ value, children, className }: { value: string; children: ReactNode; className?: string }) {
  const c = use();
  const active = c.value === value;
  return (
    <button type="button" role="tab" id={`${c.base}-tab-${value}`} aria-controls={`${c.base}-panel-${value}`}
      aria-selected={active} tabIndex={active ? 0 : -1} data-state={active ? "active" : "inactive"} onClick={() => c.setValue(value)}
      className={cn("-mb-px cursor-pointer border-b-2 border-transparent px-3 py-2 text-dense font-medium text-gray-11 transition-colors hover:text-gray-12 data-[state=active]:border-brand-9 data-[state=active]:text-gray-12", className)}>
      {children}
    </button>
  );
}

export function TabsContent({ value, children, className }: { value: string; children: ReactNode; className?: string }) {
  const c = use();
  const active = c.value === value;
  return (
    <div role="tabpanel" id={`${c.base}-panel-${value}`} aria-labelledby={`${c.base}-tab-${value}`} hidden={!active} tabIndex={0}
      className={cn("pt-4 outline-none", className)}>
      {active ? children : null}
    </div>
  );
}
