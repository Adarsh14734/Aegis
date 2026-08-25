/** Permissions — the one screen that changes anything.
 *
 *  Every other screen reads. This one edits policy.json, which the threat model
 *  calls the asset that makes every other control decorative if compromised
 *  (A7). Three rules follow from that, and they are visible in the markup:
 *
 *   1. **Nothing here decides.** Each action calls the Rust command, which
 *      shells out to `aegis policy`, which is where the gates live. If this
 *      screen has a bug, the write is still refused by Python.
 *   2. **A grant is never one click.** Widening asks for confirmation naming
 *      exactly what is being granted, in the words the user will read on the
 *      row. Narrowing does not: someone removing access in a hurry has lost
 *      nothing they cannot restore.
 *   3. **Everything reads as a sentence.** "Can read and change your Robotics
 *      folder", never "filesystem.read". Same discipline as the Activity
 *      screen's translate layer — a rule_id is not a decision anyone can make.
 *
 *  When the audit chain does not verify, the whole screen is read-only and says
 *  why. Changing the rules while the record of what happened cannot be trusted
 *  would compound the problem rather than fix it.
 */

import { useEffect, useState } from "react";
import {
  loadPermissions,
  setDeny,
  setFolder,
  type EditResult,
  type Permissions as PermissionsData,
} from "../api";

const EFFECTS = ["allow", "ask", "deny"] as const;
type EffectId = (typeof EFFECTS)[number];

const EFFECT_LABEL: Record<EffectId, string> = {
  allow: "Allow",
  ask: "Ask",
  deny: "Deny",
};

/** Ranked so "is this a grant?" is a comparison, matching policyedit.py. */
const RANK: Record<EffectId, number> = { deny: 0, ask: 1, allow: 2 };

type Pending =
  | { kind: "folder"; path: string; name: string; effect: EffectId; sentence: string }
  | { kind: "deny"; pattern: string; blocked: boolean; sentence: string };

export function Permissions() {
  const [data, setData] = useState<PermissionsData | null>(null);
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [note, setNote] = useState<string>("");
  // A refusal is not a status note. It used to share `note` and render as an
  // unstyled paragraph in the page flow, so "REFUSING: the proxy would reject
  // this policy at startup" read like body copy and the screen looked inert.
  const [failure, setFailure] = useState<string>("");

  const refresh = () =>
    loadPermissions()
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e) => setError(String(e)));

  useEffect(() => {
    refresh();
  }, []);

  if (error) {
    // This is where the reported traceback landed. `aegis policy show` failing
    // is a failure to READ, and it used to be painted in the same red the
    // tamper states use, under no heading at all — so an interpreter that
    // could not import a module looked like a security event. It is not one:
    // nothing was read, nothing was changed, and the screen says exactly that.
    return (
      <section className="screen">
        <h1>Permissions</h1>
        <div className="banner banner-caution" role="status">
          <strong>Aegis could not read your rules.</strong>
          <div style={{ marginTop: 6 }}>{error}</div>
          <div style={{ marginTop: 8 }} className="banner-remedy">
            Nothing was changed. Your rules are still whatever they were — this
            window could not open them to show you.
          </div>
        </div>
      </section>
    );
  }
  if (!data) return <section className="screen"><h1>Permissions</h1><p>Reading…</p></section>;

  const locked = !data.editable;

  const applyResult = (r: EditResult) => {
    setBusy(false);
    setPending(null);
    if (r.error) {
      setNote("");
      setFailure(r.error);
      return;
    }
    if (!r.written) {
      setFailure("");
      setNote(r.reason ?? "Nothing to change.");
      return;
    }
    setFailure("");
    setNote(
      `${r.changes.join("; ")} — this applies the next time your agent starts.`,
    );
    // Re-read rather than assume: the row must show what the policy now says,
    // not what was clicked. If a later change makes a write partially succeed,
    // this is what keeps the selector honest.
    refresh();
  };

  const commit = (p: Pending, confirmGrant: boolean) => {
    setBusy(true);
    const call =
      p.kind === "folder"
        ? setFolder(p.path, p.effect, confirmGrant)
        : setDeny(p.pattern, p.blocked, confirmGrant);
    call.then(applyResult).catch((e) => {
      setBusy(false);
      setPending(null);
      setNote("");
      setFailure(String(e));
    });
  };

  const chooseFolder = (
    folder: PermissionsData["folders"][number],
    next: EffectId,
  ) => {
    const current = folder.effect as EffectId;
    if (current === next) return;
    const widening = RANK[next] > RANK[current];
    const sentence =
      next === "allow"
        ? `Can read and change your ${folder.name} folder`
        : next === "ask"
          ? `Must ask you first before touching your ${folder.name} folder`
          : `Cannot open your ${folder.name} folder at all`;
    const p: Pending = { kind: "folder", path: folder.path, name: folder.name, effect: next, sentence };
    // Narrowing goes straight through. Only a grant stops to ask.
    if (widening) setPending(p);
    else commit(p, false);
  };

  const chooseDeny = (pattern: string, blocked: boolean) => {
    const sentence = blocked
      ? `Never open anything matching ${pattern}, in any folder`
      : `STOP blocking ${pattern}. Files matching it become readable wherever a folder already allows access`;
    const p: Pending = { kind: "deny", pattern, blocked, sentence };
    if (!blocked) setPending(p);
    else commit(p, false);
  };

  return (
    <section className="screen">
      <h1>Permissions</h1>

      {/* Locked either way — an edit made against a record nobody can vouch
          for is an edit nobody can reconstruct — but worded and coloured by
          WHY. "The chain does not verify" and "the chain could not be checked"
          are different facts, and only the first one is an accusation.
          policyedit.py decides which; this only renders it. */}
      {locked && (
        <p className={data.chain_state === "broken" ? "chain-broken" : "chain-unchecked"}>
          These controls are switched off. {data.not_editable_reason}
        </p>
      )}

      <p className="muted">{data.applies_note}</p>

      <h2>Folders</h2>
      <ul className="perm-list">
        {data.folders.map((f) => (
          <li key={f.path} className="perm-row">
            <div className="perm-what">
              <strong>{f.name}</strong>
              <span className="perm-sentence">{f.sentence}</span>
              <span className="perm-path">{f.path}</span>
            </div>
            <div className="perm-choices" role="group" aria-label={`Permission for ${f.name}`}>
              {EFFECTS.map((e) => (
                <button
                  key={e}
                  type="button"
                  disabled={locked || busy}
                  aria-pressed={f.effect === e}
                  className={f.effect === e ? "perm-choice is-on" : "perm-choice"}
                  onClick={() => chooseFolder(f, e)}
                >
                  {EFFECT_LABEL[e]}
                </button>
              ))}
            </div>
          </li>
        ))}
        {data.folders.length === 0 && (
          <li className="perm-row">
            <span className="perm-sentence">
              No folders are listed yet. Your agent cannot open anything.
            </span>
          </li>
        )}
      </ul>

      <h2>Never open these, anywhere</h2>
      <p className="muted">
        Checked before every other rule. A folder set to Allow does not override
        this list.
      </p>
      <ul className="perm-list">
        {data.deny_paths.map((d) => (
          <li key={d.pattern} className="perm-row">
            <div className="perm-what">
              <strong>{d.pattern}</strong>
              <span className="perm-sentence">{d.sentence}</span>
            </div>
            <button
              type="button"
              className="perm-choice"
              disabled={locked || busy}
              onClick={() => chooseDeny(d.pattern, false)}
            >
              Stop blocking
            </button>
          </li>
        ))}
      </ul>

      {note && <p className="perm-note">{note}</p>}

      {failure && (
        <div className="perm-error" role="alert" aria-live="assertive">
          <div className="perm-error-head">
            <span className="tag tag-blocked">Refused</span>
            <strong>Nothing was changed</strong>
          </div>
          {/* pre-wrap: the refusals are multi-line and the second line is the
              policy loader's own words. Reflowing them loses the structure that
              makes them readable. */}
          <p className="perm-error-body">{failure}</p>
          <button type="button" className="perm-choice" onClick={() => setFailure("")}>
            Dismiss
          </button>
        </div>
      )}

      {pending && (
        <div className="perm-confirm" role="alertdialog" aria-label="Confirm this grant">
          <h3>This gives your agent more access</h3>
          <p className="perm-grant">{pending.sentence}</p>
          <p className="muted">
            Removing access never asks. Adding it does, because it is the change
            that cannot be undone by itself.
          </p>
          <div className="perm-choices">
            <button type="button" disabled={busy} onClick={() => commit(pending, true)}>
              Yes, grant this
            </button>
            <button type="button" disabled={busy} onClick={() => setPending(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
