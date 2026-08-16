/** The only place the UI talks to anything outside itself.
 *
 *  Every call below is a read, with one exception: resolveApproval(), which
 *  hands an answer to the running proxy through the approval bridge. The UI
 *  has no database handle, no write path, and no way to reach audit.db —
 *  the Rust side opens it read-only and returns plain values.
 */

import type { PendingApproval, Snapshot } from "./types";

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

/** Send the human's answer to the waiting proxy.
 *
 *  This does NOT resolve the approval itself and does not touch audit.db. It
 *  writes one byte-string to the approval bridge, which types it on the
 *  proxy's terminal. approval.py parses it, proxy.py records it, exactly as if
 *  a person had answered — same code path, same audit rows, same rule_ids.
 */
export async function resolveApproval(p: PendingApproval, approve: boolean): Promise<string> {
  if (!isTauri()) return "The browser harness cannot answer a real approval.";
  return call<string>("resolve_approval", { promptId: p.prompt_id, approve });
}
