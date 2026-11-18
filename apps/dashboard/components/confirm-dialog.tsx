"use client";

import { useState, type ReactNode } from "react";

import { Button, type ButtonProps } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";

/**
 * Dangerous actions confirm and restate exactly what will happen (§7). The confirm button
 * SUBMITS a plain server-rendered <form> (by id) as its submitter, so the CSRF token, digest
 * and nonce travel exactly as before; nothing is optimistic. Optional gates:
 *   - typeToConfirm: the user must type this exact text (CRITICAL: last 6 of the action id);
 *   - reason: a required free-text field submitted with the form (reject needs a reason).
 */
export function ConfirmDialog({
  trigger, title, description, children, formId, confirmLabel, confirmVariant = "primary",
  submitName, submitValue, typeToConfirm, typeToConfirmWhat = "the last 6 characters of the action id", reason, testId,
}: {
  trigger: ReactNode; title: string; description?: ReactNode; children?: ReactNode; formId: string;
  confirmLabel: string; confirmVariant?: ButtonProps["variant"]; submitName?: string; submitValue?: string;
  typeToConfirm?: string; typeToConfirmWhat?: string; reason?: { label: string; name: string; required: boolean; placeholder?: string }; testId?: string;
}) {
  const [typed, setTyped] = useState("");
  const [why, setWhy] = useState("");
  const typedOk = !typeToConfirm || typed.trim() === typeToConfirm;
  const reasonOk = !reason?.required || why.trim().length >= 3;
  return (
    <Dialog onOpenChange={(o) => { if (!o) { setTyped(""); setWhy(""); } }}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent title={title} description={description} wide data-testid={testId}>
        <div className="space-y-4 px-5 py-4">
          {children}
          {reason ? (
            <div>
              <Label htmlFor={`${formId}-${reason.name}`}>{reason.label}</Label>
              <textarea id={`${formId}-${reason.name}`} name={reason.name} form={formId} maxLength={1024} required={reason.required}
                value={why} onChange={(e) => setWhy(e.target.value)} placeholder={reason.placeholder} rows={3}
                className="mt-1.5 w-full rounded-md border border-gray-7 bg-gray-1 px-2.5 py-2 text-dense placeholder:text-gray-10 focus-visible:border-brand-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-7/60" />
            </div>
          ) : null}
          {typeToConfirm ? (
            <div>
              <Label htmlFor={`${formId}-type`}>
                Type <code className="rounded-sm bg-gray-3 px-1 font-mono text-gray-12">{typeToConfirm}</code> ({typeToConfirmWhat}) to confirm
              </Label>
              <Input id={`${formId}-type`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} className="mt-1.5 font-mono" />
            </div>
          ) : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-5 px-5 py-3">
          <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
          <Button type="submit" form={formId} name={submitName} value={submitValue} variant={confirmVariant} disabled={!typedOk || !reasonOk}>
            {confirmLabel}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
