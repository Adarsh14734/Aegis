import { useState } from "react";
import { resolveApproval } from "../api";
import {
  approvalButtons,
  approvalHeadline,
  approvalWhy,
  shortPath,
} from "../lib/translate";
import type { Snapshot } from "../types";

/** One card, never a queue. If two requests are somehow waiting, the oldest is
 *  shown and the rest are counted — a list of decisions invites clicking
 *  through them, which is the approval fatigue C7 exists to avoid (T5). */
export function Approvals({ snap, onResolved }: { snap: Snapshot; onResolved: () => void }) {
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);
  const pending = snap.pending;

  async function answer(approve: boolean) {
    if (!pending) return;
    setBusy(true);
    try {
      setOutcome(await resolveApproval(pending, approve));
      onResolved();
    } catch (e) {
      setOutcome(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!pending) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 620 }}>
        <h1 className="screen-kicker">Approvals</h1>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <p className="empty-serif">{outcome ?? "Nothing needs your answer."}</p>
          <div className="footnote">Nothing is waiting for you.</div>
        </div>
      </div>
    );
  }

  const buttons = approvalButtons(pending);
  const bridgeReady = snap.bridge.available;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 620 }}>
      <h1 className="screen-kicker">Approvals</h1>

      <div className="card">
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div className="card-kicker">Waiting for you</div>
          <div className="card-headline">{approvalHeadline(pending)}</div>
        </div>

        {pending.paths.length > 0 && (
          <div className="card-section">
            <div className="card-section-label">The files</div>
            {pending.paths.slice(0, 8).map((p) => (
              <div className="card-line" key={p}>
                {shortPath(p)}
              </div>
            ))}
            {pending.paths.length > 8 && (
              <div className="card-line muted">…and {pending.paths.length - 8} more</div>
            )}
          </div>
        )}

        <div className="card-section">
          <div className="card-section-label">Why</div>
          <div className="card-why">{approvalWhy(pending)}</div>
        </div>

        <div className="card-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || !bridgeReady}
            onClick={() => void answer(true)}
          >
            {buttons.allow}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy || !bridgeReady}
            onClick={() => void answer(false)}
          >
            {buttons.deny}
          </button>
        </div>

        {/* Buttons that quietly do nothing are worse than buttons that say why
            they cannot. If no bridge is running, the request is still real —
            it is answered at the terminal Aegis was started from. */}
        {!bridgeReady && (
          <div className="banner banner-alarm">
            <strong>This window cannot answer it.</strong>
            <div style={{ marginTop: 6 }}>
              {snap.bridge.detail} Answer at the terminal where Aegis is running —
              the request is waiting there and will be denied on its own if
              nobody replies.
            </div>
          </div>
        )}
      </div>

      {outcome && <div className="footnote">{outcome}</div>}
      <div className="footnote">
        Aegis asks once per request. If you do nothing, the answer is no.
      </div>
    </div>
  );
}
