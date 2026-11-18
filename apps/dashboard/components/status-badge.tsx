import { Tooltip } from "@/components/ui/overlay";
import { STATUS_ICONS } from "@/components/icons";
import { cn } from "@/lib/cn";
import { EMPTY } from "@/lib/format";
import { TONE_CLASS, TONE_ICON, riskMeta, statusMeta, type StatusMeta } from "@/lib/status";

function Pill({ meta, value, className, size = "md" }: { meta: StatusMeta; value: string; className?: string; size?: "sm" | "md" | "lg" }) {
  const Icon = STATUS_ICONS[meta.icon];
  const pill = (
    <span
      data-status={value}
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-sm border font-medium",
        size === "sm" && "px-1 py-px text-[11px] leading-4",
        size === "md" && "px-1.5 py-0.5 text-caption",
        size === "lg" && "px-2.5 py-1 text-body",
        TONE_CLASS[meta.tone],
        className,
      )}
    >
      <Icon aria-hidden="true" className={cn(size === "lg" ? "size-4" : "size-3", TONE_ICON[meta.tone])} strokeWidth={2.5} />
      {meta.label}
    </span>
  );
  // Icon + text label always (never color alone); the tooltip explains it (§7).
  return meta.help ? <Tooltip content={meta.help}><span tabIndex={0} className="inline-flex rounded-sm">{pill}</span></Tooltip> : pill;
}

/** Every status in the app renders through here, driven by lib/status.ts. */
export function StatusBadge({ value, className, size }: { value: string | null | undefined; className?: string; size?: "sm" | "md" | "lg" }) {
  if (!value) return <span className="text-gray-11">{EMPTY}</span>;
  return <Pill meta={statusMeta(value)} value={value} className={className} size={size} />;
}

export function RiskBadge({ level, className, size }: { level: string | null | undefined; className?: string; size?: "sm" | "md" | "lg" }) {
  if (!level) return <span className="text-gray-11">{EMPTY}</span>;
  return <Pill meta={riskMeta(level)} value={level} className={className} size={size} />;
}
