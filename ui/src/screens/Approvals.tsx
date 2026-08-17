import { approvalButtons, approvalHeadline, approvalWhy, shortPath } from "../lib/translate";
import type { Snapshot } from "../types";

/** One card, never a queue. If two requests are somehow waiting, the oldest is
 *  shown — a list of decisions invites clicking through them, which is the
 *  approval fatigue C7 exists to avoid (T5).
 *
 *  THE BUTTONS DO NOT WORK, AND SAY SO. Answering a /dev/tty prompt from a
 *  window needs something to type on that terminal. The supervisor written for
 *  that job was removed rather than shipped unverified (S6-REPORT.md), so this
 *  screen is a viewer: it shows what is waiting, and points at the terminal
 *  where it can be answered. The buttons stay visible and disabled because
 *  hiding them would hide what the answer will be; a disabled control that
 *  explains itself is honest, an enabled one that silently does nothing is not.
 */
export function Approvals({ snap }: { snap: Snapshot }) {
  const pending = snap.pending;

  if (!pending) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 620 }}>
        <h1 className="screen-kicker">Approvals</h1>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <p className="empty-serif">Nothing needs your answer.</p>
          <div className="footnote">Nothing is waiting for you.</div>
        </div>
      </div>
    );
  }

  const buttons = approvalButtons(pending);

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
          <button type="button" className="btn btn-primary" disabled>
            {buttons.allow}
          </button>
          <button type="button" className="btn btn-secondary" disabled>
            {buttons.deny}
          </button>
        </div>

        <div className="banner banner-alarm">
          <strong>Answer this at the terminal, not here.</strong>
          <div style={{ marginTop: 6 }}>
            This window can show you what is waiting but cannot answer it. The
            request is sitting at the terminal Aegis was started from, and will
            be refused on its own if nobody replies.
          </div>
        </div>
      </div>

      <div className="footnote">
        Aegis asks once per request. If you do nothing, the answer is no.
      </div>
    </div>
  );
}
