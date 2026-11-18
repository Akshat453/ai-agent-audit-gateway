import * as React from "react";

import { cn } from "@/lib/cn";

export const inputClass =
  "h-8 w-full rounded-md border border-gray-7 bg-gray-1 px-2.5 text-dense text-gray-12 placeholder:text-gray-10 transition-colors hover:border-gray-8 focus-visible:border-brand-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-7/60 disabled:opacity-50";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(inputClass, className)} {...props} />,
);
Input.displayName = "Input";

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("block text-caption font-medium text-gray-11", className)} {...props} />;
}

export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd className={cn("inline-flex h-5 min-w-5 items-center justify-center rounded-sm border border-gray-7 bg-gray-2 px-1 font-mono text-[11px] font-medium text-gray-11", className)}>
      {children}
    </kbd>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cn("animate-pulse rounded-md bg-gray-4", className)} />;
}
