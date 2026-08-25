/** The only place the UI talks to anything outside itself.
 *
 *  Reads: the UI has no database handle and no way to reach audit.db. The Rust
 *  side opens it read-only and returns plain values, and audit.py remains its
 *  single writer.
 *
 *  S10 adds THREE calls that write, and only one file: policy.json, from the
 *  Permissions screen. They decide nothing — each one shells out through Rust
 *  to `aegis policy`, where the gates live (the chain must verify, the proxy's
 *  own loader must accept the document, a grant must be confirmed, the write is
 *  atomic at 0600). A bug on this side fails closed, because this side does not
 *  implement the rules it would have to bypass.
 */

import type { ChainState, Snapshot } from "./types";

export type PermissionFolder = {
  path: string;
  name: string;
  effect: "allow" | "ask" | "deny";
  label: string;
  sentence: string;
};

export type Permissions = {
  policy_path: string;
  folders: PermissionFolder[];
  deny_paths: { pattern: string; sentence: string }[];
  editable: boolean;
  not_editable_reason: string;
  /** Why the screen is locked, as a state rather than as prose. The screen
   *  words "the checker could not run" and "your log was altered" differently,
   *  and it must not have to pattern-match a sentence to tell them apart. */
  chain_state?: ChainState;
  chain_detail?: string;
  applies_note: string;
};

export type EditResult = {
  written: boolean;
  path?: string;
  changes: string[];
  granted: boolean;
  error?: string;
  reason?: string;
};

/** Tauri v2 injects this before any app code runs. */
export const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export async function loadSnapshot(): Promise<Snapshot> {
  if (!isTauri()) {
    // Browser dev harness only — used to check the layout against the design
    // reference without a Rust toolchain. Marked sample_data so the app paints
    // a banner; it can never be reached from the packaged binary.
    const { sampleSnapshot } = await import("./devFixture");
    return sampleSnapshot();
  }
  return call<Snapshot>("snapshot");
}

export async function loadPermissions(): Promise<Permissions> {
  if (!isTauri()) {
    const { samplePermissions } = await import("./devFixture");
    return samplePermissions();
  }
  return call<Permissions>("permissions");
}

/** Set one folder to allow / ask / deny.
 *
 *  `confirmGrant` is passed, never inferred here. Python refuses a widening
 *  write without it, so forgetting to ask the user is a refusal rather than a
 *  silent grant.
 */
export async function setFolder(
  path: string,
  effect: string,
  confirmGrant: boolean,
): Promise<EditResult> {
  if (!isTauri()) return { written: false, changes: [], granted: false, reason: "browser harness" };
  return call<EditResult>("set_folder", { path, effect, confirmGrant });
}

export async function setDeny(
  pattern: string,
  blocked: boolean,
  confirmGrant: boolean,
): Promise<EditResult> {
  if (!isTauri()) return { written: false, changes: [], granted: false, reason: "browser harness" };
  return call<EditResult>("set_deny", { pattern, blocked, confirmGrant });
}

/* resolveApproval() was removed with the approval bridge (S6, 2026-08-17).
   The UI has no way to answer a prompt and does not pretend to: Approvals
   shows what is waiting and says where to answer it. See S6-REPORT.md. */
