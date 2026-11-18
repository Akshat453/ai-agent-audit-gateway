import * as React from "react";

import { cn } from "@/lib/cn";

/** Thin-bordered surface (no shadow: shadows are for overlays only, §3.3). */
export function Card({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return <section className={cn("rounded-md border border-gray-6 bg-gray-1", className)} {...props} />;
}

export function CardHeader({ title, description, action, className, id }: {
  title: React.ReactNode; description?: React.ReactNode; action?: React.ReactNode; className?: string; id?: string;
}) {
  return (
    <header className={cn("flex items-start justify-between gap-3 border-b border-gray-5 px-4 py-3", className)}>
      <div className="min-w-0">
        <h2 id={id} className="text-section font-semibold text-gray-12">{title}</h2>
        {description ? <p className="mt-0.5 text-caption text-gray-11">{description}</p> : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </header>
  );
}

export function CardBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...props} />;
}
