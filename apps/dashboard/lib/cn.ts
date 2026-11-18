import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/** tailwind-merge must know the custom type scale (globals.css @theme): otherwise it reads
 *  `text-body` as a text COLOR and drops a real color like `text-white` next to it. */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["title", "section", "body", "dense", "caption", "kpi"] }],
    },
  },
});

/** Merge Tailwind classes (shadcn/ui convention). */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
