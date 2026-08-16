import { activityLine, formatTime } from "../lib/translate";
import type { Snapshot } from "../types";

/** Every row is one audit row, in the order it happened. Blocked rows carry
 *  the deep red and a Blocked tag; nothing else in the product uses that red. */
export function Activity({ snap }: { snap: Snapshot }) {
  const rows = snap.recent;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 700 }}>
      <h1 className="screen-kicker">Activity</h1>
      <p className="lede">Everything the agents on this machine did, in the order it happened.</p>

      {rows.length === 0 ? (
        <p className="lede muted">Nothing has happened yet.</p>
      ) : (
        <div className="stack">
          {rows.map((row) => {
            const { text, kind } = activityLine(row);
            return (
              <div className="act-row" key={row.id}>
                <div className="act-time">{formatTime(row.ts)}</div>
                <div className={`act-text${kind === "plain" ? "" : ` ${kind}`}`}>{text}</div>
                {kind === "blocked" && <span className="tag tag-blocked">Blocked</span>}
              </div>
            );
          })}
        </div>
      )}

      <div className="footnote">
        {/* No retention claim: audit.py keeps everything and nothing prunes it.
            Saying "kept for two weeks" would be a promise the code does not make. */}
        Aegis keeps every entry. Nothing here is ever deleted automatically.
      </div>
    </div>
  );
}
