import { relativeTime, shortPath, statusSentence } from "../lib/translate";
import type { Snapshot } from "../types";

/** One sentence, three counters, four facts. Nothing here is computed from
 *  anything but the audit counters and the policy file. */
export function Status({ snap }: { snap: Snapshot }) {
  const { counters, policy } = snap;

  const rows: { label: string; value: string }[] = [
    {
      label: "Agents connected",
      // The policy names tools, not agents. Saying so is better than guessing
      // a product name Aegis has no way to know.
      value: policy.loaded
        ? policy.tools.length > 0
          ? `${policy.tools.length} tools allowed by your rules`
          : "No tools are allowed by your rules"
        : "Unknown — the rules file could not be read",
    },
    {
      label: "Folders it watches",
      value: policy.loaded
        ? policy.workspace_roots.map(shortPath).join(", ") || "None"
        : "Unknown",
    },
    {
      label: "Folders it never opens",
      value: policy.loaded ? policy.deny_paths.join(", ") || "None" : "Unknown",
    },
    {
      label: "Last check",
      value: relativeTime(snap.recent[0]?.ts ?? null),
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24, maxWidth: 640 }}>
      <h1 className="screen-kicker">Status</h1>
      <p className="serif-sentence">{statusSentence(counters)}</p>

      <div className="counters">
        <div className="counter counter-lead">
          <div className="counter-num">{counters.waiting}</div>
          <div className="counter-label">Waiting for your answer</div>
        </div>
        <div className="counter">
          <div className="counter-num">{counters.actions_today}</div>
          <div className="counter-label">Things agents did today</div>
        </div>
        <div className="counter">
          <div className={`counter-num${counters.blocked_today > 0 ? " blocked" : ""}`}>
            {counters.blocked_today}
          </div>
          <div className="counter-label">Stopped by Aegis</div>
        </div>
      </div>

      <div className="kv">
        {rows.map((r) => (
          <div className="kv-row" key={r.label}>
            <div className="kv-label">{r.label}</div>
            <div className="kv-value">{r.value}</div>
          </div>
        ))}
      </div>

      {!policy.loaded && policy.error && (
        <div className="footnote">Rules file: {policy.error}</div>
      )}
    </div>
  );
}
