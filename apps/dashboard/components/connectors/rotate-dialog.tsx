"use client";

import { KeyRound } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";
import { CREDENTIAL_LABEL } from "@/lib/connector-form";

/** Rotate credentials (C2): password inputs that are never pre-filled; the plain form POST
 *  sends them only to the dashboard's route handler, then the page reloads without them. */
export function RotateDialog({ connectorId, typeId, fields, csrf, version }: {
  connectorId: string; typeId: string; fields: string[]; csrf: string; version: number;
}) {
  return (
    <Dialog>
      <DialogTrigger asChild><Button size="sm"><KeyRound />Rotate credentials</Button></DialogTrigger>
      <DialogContent title="Rotate credentials" description={`Replaces the sealed credentials (now version ${version}). The old values are destroyed. Leave a field empty to drop it.`} data-testid="rotate-dialog">
        <form method="post" action={`/api/connectors/${connectorId}/rotate`} autoComplete="off">
          <input type="hidden" name="csrf" value={csrf} />
          <input type="hidden" name="type_id" value={typeId} />
          <div className="space-y-4 px-5 py-4">
            {fields.map((f) => (
              <div key={f}>
                <Label htmlFor={`rot-${f}`}>New {CREDENTIAL_LABEL[f] ?? f}</Label>
                <Input id={`rot-${f}`} name={`cred.${f}`} type="password" autoComplete="new-password" spellCheck={false} className="mt-1.5 font-mono" />
              </div>
            ))}
          </div>
          <div className="flex justify-end gap-2 border-t border-gray-5 px-5 py-3">
            <DialogClose asChild><Button variant="secondary">Cancel</Button></DialogClose>
            <Button type="submit" variant="primary">Rotate</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
