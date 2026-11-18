"use client";

import { setNonce } from "get-nonce";

/** Radix's scroll lock (react-remove-scroll -> react-style-singleton) injects one <style> tag
 *  when a modal opens; it reads the CSP nonce from get-nonce. We hand it this request's nonce so
 *  the tag is allowed by `style-src 'nonce-…'` instead of relaxing the CSP (ADR-0033 §2). */
export function NonceSetter({ nonce }: { nonce?: string }) {
  if (nonce) setNonce(nonce);
  return null;
}
