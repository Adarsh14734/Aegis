import type { Snapshot } from "../types";

/** Data flow asks four questions: what left, where it went, why, how much.
 *
 *  The audit database can answer one of them. An allowed egress row records
 *  `matched allow rule` and nothing more — the destination host appears only
 *  in the reason of a *denial*, which by definition never left the machine —
 *  and there is no size column anywhere in the schema (aegis/audit.py).
 *
 *  The first version rendered the table anyway, which produced rows reading
 *  "A request from fetch / Not recorded / Not recorded", repeated. That is
 *  worse than nothing: a table implies its columns are answerable, and a
 *  screenful of them implies Aegis is watching traffic it cannot see. So the
 *  screen says what it does not know, once, and stops.
 *
 *  This is not an empty state waiting for data. It is a missing capability,
 *  and it stays this way until audit.py records destination and size on
 *  allowed egress — a hash-chained schema change, filed for S8.
 */
export function DataFlow({ snap }: { snap: Snapshot }) {
  // Counted, not listed: the log does know that *something* was allowed out,
  // which is the one honest number on this screen.
  const allowedEgress = snap.recent.filter(
    (r) =>
      r.effect === "allow" &&
      (/fetch|http|url|web|request|api|curl|browse|download/i.test(r.tool) ||
        r.reason.includes("substituted credential handle")),
  ).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 760 }}>
      <h1 className="screen-kicker">Data flow</h1>

      <p className="serif-sentence" style={{ maxWidth: "30ch" }}>
        Aegis cannot yet tell you what left this machine.
      </p>

      <p className="lede">
        It records that a request was allowed, but not where the request went or
        how large it was — so this screen cannot answer its own question, and it
        is not going to guess. Aegis does not read the traffic itself.
      </p>

      <div className="kv">
        <div className="kv-row">
          <div className="kv-label">Requests allowed out</div>
          <div className="kv-value">
            {allowedEgress === 0
              ? "None in the entries held here"
              : `${allowedEgress} in the entries held here`}
          </div>
        </div>
        <div className="kv-row">
          <div className="kv-label">Where they went</div>
          <div className="kv-value muted">Not recorded</div>
        </div>
        <div className="kv-row">
          <div className="kv-label">How much was sent</div>
          <div className="kv-value muted">Not recorded</div>
        </div>
      </div>

      <p className="lede muted" style={{ lineHeight: 1.6 }}>
        Requests Aegis blocked are the ones it knows the destination for, because
        it had to read the address to refuse it. Those never left the machine, so
        they are not what this screen is for. You can see them on Activity.
      </p>
    </div>
  );
}
