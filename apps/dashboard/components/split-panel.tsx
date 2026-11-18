"use client";

import { ExternalLink, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** Right-side details panel for the selected table row (§4). Resizable by dragging its left
 *  edge (or with the keyboard on the handle); the width is applied through the CSSOM after
 *  mount, never as a server-rendered style attribute (strict CSP). Esc closes it. */
export function SplitPanel({ title, fullHref, children }: { title: ReactNode; fullHref?: string; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  const [width, setWidth] = useState(440);
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  const close = () => {
    const sp = new URLSearchParams(params.toString());
    sp.delete("sel");
    const qs = sp.toString();
    router.push(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

  useEffect(() => {
    let w = 440;
    try {
      w = Number(window.sessionStorage.getItem("agw-split-w")) || 440;
    } catch {
      /* storage blocked: default width */
    }
    if (ref.current) ref.current.style.width = `${w}px`;
    setWidth(w);
  }, []);

  const resize = (to: number) => {
    const w = Math.min(Math.max(320, to), Math.min(900, window.innerWidth - 360));
    if (ref.current) ref.current.style.width = `${w}px`;
    setWidth(w);
    try {
      window.sessionStorage.setItem("agw-split-w", String(w));
    } catch {
      /* ignore */
    }
  };

  const onPointerDown = (e: React.PointerEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startW = ref.current?.getBoundingClientRect().width ?? 440;
    const move = (ev: PointerEvent) => resize(startW + (startX - ev.clientX));
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <aside ref={ref} aria-label="Details" className="relative hidden w-[440px] shrink-0 animate-slide rounded-md border border-gray-6 bg-gray-1 lg:block">
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize details panel"
        aria-valuenow={width}
        aria-valuemin={320}
        aria-valuemax={900}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onKeyDown={(e) => {
          const w = ref.current?.getBoundingClientRect().width ?? 440;
          if (e.key === "ArrowLeft") resize(w + 24);
          if (e.key === "ArrowRight") resize(w - 24);
        }}
        className="absolute inset-y-0 -left-1.5 w-3 cursor-col-resize rounded-full hover:bg-brand-5 focus-visible:bg-brand-5"
      />
      <div className="sticky top-14 flex max-h-[calc(100vh-5rem)] flex-col">
        <div className="flex items-center justify-between gap-2 border-b border-gray-5 px-4 py-3">
          <h2 className="truncate text-section font-semibold">{title}</h2>
          <div className="flex items-center gap-1">
            {fullHref ? (
              <a href={fullHref} className="inline-flex items-center gap-1 rounded-sm px-1.5 py-1 text-caption font-medium text-brand-11 hover:bg-gray-3">
                Open full page<ExternalLink aria-hidden="true" className="size-3.5" />
              </a>
            ) : null}
            <button type="button" onClick={close} aria-label="Close details" className="rounded-sm p-1 text-gray-11 hover:bg-gray-4 hover:text-gray-12">
              <X className="size-4" />
            </button>
          </div>
        </div>
        <div className="overflow-y-auto p-4">{children}</div>
      </div>
    </aside>
  );
}
