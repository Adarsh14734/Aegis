/** The only place the UI talks to anything outside itself.
 *
 *  Every call below is a read. The UI has no database handle, no write path,
 *  and no way to reach audit.db — the Rust side opens it read-only and
 *  returns plain values. There is no command that changes anything.
 */

import type { Snapshot } from "./types";

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

/* resolveApproval() was removed with the approval bridge (S6, 2026-08-17).
   The UI has no way to answer a prompt and does not pretend to: Approvals
   shows what is waiting and says where to answer it. See S6-REPORT.md. */
