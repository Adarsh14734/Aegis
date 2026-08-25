import { useCallback, useEffect, useState } from "react";
import { loadSnapshot } from "./api";
import { chainBanner, formatSince } from "./lib/translate";
import { Activity } from "./screens/Activity";
import { Approvals } from "./screens/Approvals";
import { DataFlow } from "./screens/DataFlow";
import { Permissions } from "./screens/Permissions";
import { Status } from "./screens/Status";
import type { Snapshot } from "./types";

type ScreenId = "status" | "activity" | "approvals" | "permissions" | "flow";

const SCREENS: { id: ScreenId; label: string }[] = [
  { id: "status", label: "Status" },
  { id: "activity", label: "Activity" },
  { id: "approvals", label: "Approvals" },
  { id: "permissions", label: "Permissions" },
  { id: "flow", label: "Data flow" },
];

/** Poll rather than watch. The audit database is append-only and low-volume,
 *  and a 2s read-only query is cheaper to reason about than a file watcher
 *  that has to decide what a partial write means. */
const POLL_MS = 2000;

export default function App() {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [screen, setScreen] = useState<ScreenId>("status");
  const [loadError, setLoadError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSnap(await loadSnapshot());
      setLoadError(null);
    } catch (e) {
      setLoadError(String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const waiting = snap?.counters.waiting ?? 0;
  const banner = snap
    ? chainBanner(snap.chain)
    : { tone: "none" as const, headline: "", body: "", remedy: "", distrustRows: false };

  return (
    <div className="window">
      <nav className="nav">
        {/* Space for the window controls macOS draws itself. The titlebar is
            hidden (titleBarStyle: Overlay) so the native buttons float here;
            the app must not draw its own set underneath them. */}
        <div className="nav-lights" aria-hidden="true" />
        <div className="nav-title">Aegis</div>
        <div className="nav-items">
          {SCREENS.map((s) => (
            <button
              key={s.id}
              type="button"
              className="nav-item"
              aria-current={screen === s.id ? "page" : undefined}
              onClick={() => setScreen(s.id)}
            >
              <span>{s.label}</span>
              <span className="nav-badge">
                {s.id === "approvals" && waiting > 0 ? String(waiting) : ""}
              </span>
            </button>
          ))}
        </div>
        <div className="nav-foot">{formatSince(snap?.running_since ?? null)}</div>
      </nav>

      <main className="main">
        {loadError && (
          <div className="banner banner-alarm" style={{ marginBottom: 22 }}>
            <strong>Aegis cannot read its own records.</strong>
            <div style={{ marginTop: 6 }}>{loadError}</div>
          </div>
        )}

        {snap?.sample_data && (
          <div className="banner banner-dev" style={{ marginBottom: 22 }}>
            SAMPLE DATA — this is the browser layout harness, not your audit log.
            Nothing on this screen came from Aegis.
          </div>
        )}

        {/* Anything the chain check has to say is shown before anything
            derived from the rows. Rows are still listed underneath — hiding
            them would destroy the operator's only view of what happened — but
            never as if trustworthy.

            Two banners, not one, and never interchangeable. `alarm` means a
            verdict was reached and the log does not hash to itself. `caution`
            means no verdict was reached at all. The old code chose between
            them on `chain.checked`, which the Rust side set from the
            verifier's exit code; a verifier that crashed exits 1, and so does
            a verifier that found tampering, so a wrong Python interpreter
            painted the tamper alarm. See chainBanner(). */}
        {snap && banner.tone !== "none" && (
          <div
            className={`banner ${banner.tone === "alarm" ? "banner-alarm" : "banner-caution"}`}
            role={banner.tone === "alarm" ? "alert" : "status"}
            style={{ marginBottom: 22 }}
          >
            <strong>{banner.headline}</strong>
            <div style={{ marginTop: 6 }}>{banner.body}</div>
            {banner.remedy && (
              <div style={{ marginTop: 8 }} className="banner-remedy">
                {banner.remedy}
              </div>
            )}
          </div>
        )}

        {snap === null && !loadError && <p className="lede muted">Reading the audit log…</p>}

        {snap && screen === "status" && <Status snap={snap} />}
        {snap && screen === "activity" && <Activity snap={snap} />}
        {snap && screen === "approvals" && <Approvals snap={snap} />}
        {snap && screen === "flow" && <DataFlow snap={snap} />}
        {screen === "permissions" && <Permissions />}
      </main>
    </div>
  );
}
