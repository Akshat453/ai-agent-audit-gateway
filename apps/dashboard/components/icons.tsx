import {
  Anchor, Ban, Box, Check, CircleAlert, CircleDot, CircleHelp, Clock, Link2, Lock, Send, ShieldCheck, X,
  type LucideIcon,
} from "lucide-react";

import type { IconName } from "@/lib/status";

export const STATUS_ICONS: Record<IconName, LucideIcon> = {
  check: Check, x: X, alert: CircleAlert, clock: Clock, help: CircleHelp, shield: ShieldCheck,
  link: Link2, anchor: Anchor, lock: Lock, circle: CircleDot, ban: Ban, send: Send, box: Box,
};
