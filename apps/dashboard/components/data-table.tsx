"use client";

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type VisibilityState,
} from "@tanstack/react-table";
import {
  ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Columns3, Link2, RefreshCw, Search, X,
} from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState, useTransition, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/input";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger,
} from "@/components/ui/menu";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { count } from "@/lib/format";

/**
 * The ONE list component (16-dashboard-design.md §5). Server-side sort / filter / pagination:
 * every piece of table state lives in the URL (shareable, survives refresh, back button works);
 * changing it navigates and the SERVER page re-fetches. The selected row (`sel`) opens a split
 * panel the server renders (`panel` prop). Polls with router.refresh(), paused while hidden.
 */
export type FilterField = { key: string; label: string; values?: string[] };
export type QuickFilter = { label: string; params: Record<string, string | null> };

type Props<T> = {
  label: string;
  columns: ColumnDef<T, unknown>[];
  rows: T[];
  total: number;
  rowId: (row: T) => string;
  pageSize: number;
  filterFields: FilterField[];
  quickFilters?: QuickFilter[];
  sortable?: string[];
  defaultSort?: { key: string; order: "asc" | "desc" };
  pollSeconds?: number;
  fetchedAt: string;
  panel?: ReactNode;
  empty: ReactNode;
  rowHref?: (row: T) => string;
};

const PARAM_SORT = "sort";
const PARAM_ORDER = "order";
const PARAM_PAGE = "page";
const PARAM_SEL = "sel";

export function DataTable<T>(props: Props<T>) {
  const { columns, rows, total, rowId, pageSize, filterFields, quickFilters = [], sortable = [], pollSeconds = 10 } = props;
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, startTransition] = useTransition();
  const [visibility, setVisibility] = useState<VisibilityState>({});
  const [cursor, setCursor] = useState(0);
  const filterRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTableSectionElement>(null);

  const navigate = useCallback(
    (changes: Record<string, string | null>, opts: { resetPage?: boolean } = {}) => {
      const sp = new URLSearchParams(params.toString());
      for (const [k, v] of Object.entries(changes)) {
        if (v === null || v === "") sp.delete(k);
        else sp.set(k, v);
      }
      if (opts.resetPage) sp.delete(PARAM_PAGE);
      const qs = sp.toString();
      startTransition(() => router.push(qs ? `${pathname}?${qs}` : pathname, { scroll: false }));
    },
    [params, pathname, router],
  );

  const sortKey = params.get(PARAM_SORT) ?? props.defaultSort?.key ?? "";
  const sortOrder = (params.get(PARAM_ORDER) ?? props.defaultSort?.order ?? "asc") as "asc" | "desc";
  const page = Math.max(1, Number(params.get(PARAM_PAGE) ?? "1") || 1);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const selected = params.get(PARAM_SEL);

  const table = useReactTable({
    data: rows,
    columns,
    getRowId: (r) => rowId(r),
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
    manualPagination: true,
    manualFiltering: true,
    pageCount: pages,
    state: { columnVisibility: visibility },
    onColumnVisibilityChange: setVisibility,
  });

  // ---- token filters: "field = value" chips mapped to URL params
  const activeTokens = filterFields.filter((f) => params.get(f.key)).map((f) => ({ ...f, value: params.get(f.key) as string }));
  const [draft, setDraft] = useState("");
  const [hint, setHint] = useState<string | null>(null);
  const applyDraft = () => {
    const m = draft.trim().match(/^([a-z_]+)\s*(?:=|:)\s*(.+)$/i);
    const name = (m?.[1] ?? "").toLowerCase();
    const field = m ? filterFields.find((f) => f.key === name || f.label.toLowerCase() === name) : undefined;
    if (!m || !field) {
      setHint(`Use field = value, e.g. ${filterFields[0]?.key ?? "field"} = ${filterFields[0]?.values?.[0] ?? "value"}. Fields: ${filterFields.map((f) => f.key).join(", ")}`);
      return;
    }
    const value = (m[2] ?? "").trim();
    const canonical = field.values?.find((v) => v.toLowerCase() === value.toLowerCase()) ?? value;
    if (field.values && !field.values.includes(canonical)) {
      setHint(`${field.label} must be one of: ${field.values.join(", ")}`);
      return;
    }
    setHint(null);
    setDraft("");
    navigate({ [field.key]: canonical }, { resetPage: true });
  };

  // ---- polling (paused while the tab is hidden) + "updated N s ago"
  const [ago, setAgo] = useState(0);
  useEffect(() => {
    const fetched = Date.parse(props.fetchedAt);
    const tick = () => setAgo(Math.max(0, Math.round((Date.now() - fetched) / 1000)));
    tick();
    const id = setInterval(() => {
      tick();
      if (document.visibilityState === "visible" && Date.now() - fetched >= pollSeconds * 1000) {
        startTransition(() => router.refresh());
      }
    }, 1000);
    return () => clearInterval(id);
  }, [props.fetchedAt, pollSeconds, router]);

  // ---- keyboard: "/" focuses the filter, j/k move, Enter opens, Esc closes the panel
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      const typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
      if (e.key === "/" && !typing) {
        e.preventDefault();
        filterRef.current?.focus();
        return;
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "j" || e.key === "k") {
        e.preventDefault();
        setCursor((c) => {
          const n = Math.min(rows.length - 1, Math.max(0, c + (e.key === "j" ? 1 : -1)));
          bodyRef.current?.querySelectorAll<HTMLElement>("tr[data-row]")[n]?.focus();
          return n;
        });
      } else if (e.key === "Escape" && selected) {
        navigate({ [PARAM_SEL]: null });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [rows.length, selected, navigate]);

  const select = (id: string) => navigate({ [PARAM_SEL]: selected === id ? null : id });

  const sortHeader = (key: string, label: ReactNode) => {
    if (!sortable.includes(key)) return label;
    const active = sortKey === key;
    const next = active && sortOrder === "asc" ? "desc" : "asc";
    const Icon = !active ? ArrowUpDown : sortOrder === "asc" ? ArrowUp : ArrowDown;
    return (
      <button type="button" onClick={() => navigate({ [PARAM_SORT]: key, [PARAM_ORDER]: next }, { resetPage: true })}
        className="inline-flex cursor-pointer items-center gap-1 rounded-sm hover:text-gray-12" aria-label={`Sort by ${typeof label === "string" ? label : key}`}>
        {label}
        <Icon aria-hidden="true" className={cn("size-3", active ? "text-gray-12" : "text-gray-9")} />
      </button>
    );
  };

  const visibleCols = table.getAllLeafColumns();
  const ariaSort = (key: string) => (sortKey === key ? (sortOrder === "asc" ? "ascending" : "descending") : undefined);

  return (
    <div className="flex min-w-0 gap-4">
      <div className="min-w-0 flex-1">
        {/* toolbar */}
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative flex min-w-64 flex-1 flex-wrap items-center gap-1.5 rounded-md border border-gray-7 bg-gray-1 px-2 py-1 focus-within:border-brand-8 focus-within:ring-2 focus-within:ring-brand-7/60">
            <Search aria-hidden="true" className="size-4 text-gray-11" />
            {activeTokens.map((t) => (
              <span key={t.key} className="inline-flex items-center gap-1 rounded-sm border border-gray-6 bg-gray-3 py-0.5 pl-1.5 pr-0.5 text-caption">
                <span className="text-gray-11">{t.label}</span><span className="text-gray-11">=</span><span className="font-medium">{t.value}</span>
                <button type="button" aria-label={`Remove filter ${t.label} = ${t.value}`} onClick={() => navigate({ [t.key]: null }, { resetPage: true })}
                  className="rounded-sm p-0.5 text-gray-11 hover:bg-gray-5"><X className="size-3" /></button>
              </span>
            ))}
            <input
              ref={filterRef}
              value={draft}
              onChange={(e) => { setDraft(e.target.value); setHint(null); }}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); applyDraft(); } }}
              aria-label={`Filter ${props.label} (field = value)`}
              placeholder={activeTokens.length ? "" : `Filter: ${filterFields.map((f) => `${f.key} = …`).join(", ")}`}
              list={`${props.label}-filter-hints`}
              className="h-6 min-w-40 flex-1 bg-transparent text-dense outline-none placeholder:text-gray-10"
            />
            <datalist id={`${props.label}-filter-hints`}>
              {filterFields.flatMap((f) => (f.values ?? []).map((v) => <option key={`${f.key}${v}`} value={`${f.key} = ${v}`} />))}
            </datalist>
            <Kbd className="hidden sm:inline-flex">/</Kbd>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="secondary" size="md" aria-label="Choose visible columns"><Columns3 />Columns</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Visible columns</DropdownMenuLabel>
              {visibleCols.filter((c) => c.getCanHide()).map((c) => (
                <DropdownMenuItem key={c.id} onSelect={(e) => { e.preventDefault(); c.toggleVisibility(); }}>
                  <span className={cn("size-3.5 rounded-sm border", c.getIsVisible() ? "border-brand-9 bg-brand-9" : "border-gray-8")} aria-hidden="true" />
                  <span>{String(c.columnDef.meta && (c.columnDef.meta as { label?: string }).label || c.id)}</span>
                  <span className="sr-only">{c.getIsVisible() ? "(shown)" : "(hidden)"}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="secondary" aria-label="Copy a link to this view" onClick={async () => {
            try { await navigator.clipboard.writeText(window.location.href); toast("Link to this view copied", { tone: "ok" }); } catch { toast("Copy the address bar to share this view"); }
          }}><Link2 />Share view</Button>
          <Button variant="ghost" onClick={() => startTransition(() => router.refresh())} aria-label="Refresh now">
            <RefreshCw className={cn(pending && "animate-spin")} />
            <span className="tabular text-caption" aria-live="off" data-testid="updated-ago">updated {ago} s ago</span>
          </Button>
        </div>
        {hint ? <p role="status" className="-mt-1 mb-2 text-caption text-warn-12">{hint}</p> : null}
        {quickFilters.length ? (
          <div className="mb-3 flex flex-wrap items-center gap-1.5" aria-label="Quick filters" role="group">
            {quickFilters.map((q) => {
              const on = Object.entries(q.params).every(([k, v]) => (params.get(k) ?? null) === v);
              return (
                <button key={q.label} type="button" aria-pressed={on} onClick={() => navigate(q.params, { resetPage: true })}
                  className={cn("cursor-pointer rounded-full border px-2.5 py-0.5 text-caption font-medium transition-colors",
                    on ? "border-brand-8 bg-brand-3 text-brand-11" : "border-gray-6 bg-gray-1 text-gray-11 hover:bg-gray-3")}>
                  {q.label}
                </button>
              );
            })}
          </div>
        ) : null}

        {/* table */}
        <div className={cn("overflow-x-auto rounded-md border border-gray-6 transition-opacity", pending && "opacity-70")}>
          <table aria-label={props.label} aria-busy={pending} className="w-full border-collapse text-dense">
            <thead className="bg-gray-2">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => {
                    const meta = (h.column.columnDef.meta ?? {}) as { label?: string; numeric?: boolean; sortKey?: string };
                    const content = flexRender(h.column.columnDef.header, h.getContext());
                    return (
                      <th key={h.id} scope="col" aria-sort={meta.sortKey ? ariaSort(meta.sortKey) : undefined}
                        className={cn("h-9 whitespace-nowrap border-b border-gray-6 px-3 text-left text-caption font-medium text-gray-11", meta.numeric && "text-right")}>
                        {meta.sortKey ? sortHeader(meta.sortKey, content) : content}
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody ref={bodyRef}>
              {table.getRowModel().rows.map((row, i) => {
                const id = row.id;
                const isSel = selected === id;
                return (
                  <tr
                    key={id}
                    data-row={id}
                    tabIndex={0}
                    aria-selected={isSel}
                    onFocus={() => setCursor(i)}
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest("a,button,input")) return;
                      select(id);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && e.target === e.currentTarget) {
                        e.preventDefault();
                        if (e.shiftKey && props.rowHref) router.push(props.rowHref(row.original));
                        else select(id);
                      }
                    }}
                    className={cn(
                      "h-[var(--row-h)] cursor-pointer border-b border-gray-4 outline-none transition-colors last:border-b-0 hover:bg-gray-2 focus-visible:bg-brand-2 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-brand-8",
                      isSel && "bg-brand-3 hover:bg-brand-3",
                      cursor === i && "focus:bg-brand-2",
                    )}
                  >
                    {row.getVisibleCells().map((cell) => {
                      const meta = (cell.column.columnDef.meta ?? {}) as { numeric?: boolean };
                      return (
                        <td key={cell.id} className={cn("whitespace-nowrap px-3 align-middle", meta.numeric && "tabular text-right")}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {rows.length === 0 ? <div className="border-t border-gray-4">{props.empty}</div> : null}
        </div>

        {/* pagination */}
        <nav aria-label="Pagination" className="mt-3 flex items-center justify-between text-caption text-gray-11">
          <span className="tabular">
            {total === 0 ? "No rows" : `${count((page - 1) * pageSize + 1)}–${count(Math.min(total, page * pageSize))} of ${count(total)}`}
          </span>
          <div className="flex items-center gap-1">
            <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => navigate({ [PARAM_PAGE]: page - 1 > 1 ? String(page - 1) : null })} aria-label="Previous page"><ChevronLeft />Prev</Button>
            <span className="tabular px-2">Page {page} of {pages}</span>
            <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => navigate({ [PARAM_PAGE]: String(page + 1) })} aria-label="Next page">Next<ChevronRight /></Button>
          </div>
        </nav>
      </div>
      {selected && props.panel ? props.panel : null}
    </div>
  );
}

