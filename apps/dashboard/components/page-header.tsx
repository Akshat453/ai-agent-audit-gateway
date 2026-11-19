import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

import { ViewToggle } from "@/components/humanize/view-toggle";
import { HelpButton } from "@/components/shell/help";

export type Crumb = { label: string; href?: string };

/** Breadcrumbs, then title + one-line description + "?" help + right-aligned actions (§4). */
export function PageHeader({ title, description, crumbs = [], help, actions, meta, toggle = true }: {
  title: ReactNode; description?: ReactNode; crumbs?: Crumb[]; help?: string; actions?: ReactNode; meta?: ReactNode; toggle?: boolean;
}) {
  return (
    <header className="mb-6">
      {crumbs.length ? (
        <nav aria-label="Breadcrumb" className="mb-2">
          <ol className="flex flex-wrap items-center gap-1 text-caption text-gray-11">
            {crumbs.map((c, i) => (
              <li key={`${c.label}-${i}`} className="flex items-center gap-1">
                {i > 0 ? <ChevronRight aria-hidden="true" className="size-3 text-gray-9" /> : null}
                {c.href ? <a href={c.href} className="text-gray-11 hover:text-gray-12">{c.label}</a> : <span aria-current="page" className="text-gray-12">{c.label}</span>}
              </li>
            ))}
          </ol>
        </nav>
      ) : null}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-title font-semibold tracking-tight text-gray-12">{title}</h1>
            {help ? <HelpButton topic={help} /> : null}
          </div>
          {description ? <p className="mt-1 max-w-3xl text-body text-gray-11">{description}</p> : null}
          {meta ? <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div> : null}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {actions}
          {toggle ? <ViewToggle /> : null}
        </div>
      </div>
    </header>
  );
}
