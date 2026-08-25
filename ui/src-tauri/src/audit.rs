//! Read-only access to audit.db, and chain verification by delegation.

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub ts: f64,
    pub tool: String,
    pub effect: String,
    pub rule_id: String,
    pub reason: String,
    pub paths: Vec<String>,
}

#[derive(Serialize)]
pub struct Counters {
    pub actions_today: i64,
    pub waiting: i64,
    pub blocked_today: i64,
}

/// The three things the chain check can report, and the reason they are three.
///
/// `Broken` means the verifier ran, reached a verdict, and the verdict was that
/// the log does not hash to itself. `Unchecked` means no verdict was reached at
/// all — the verifier could not be found, could not start, or died. They used
/// to collapse into one because the code read `exit != 0`, and CPython exits 1
/// on an uncaught exception exactly as verify.py exits 1 on a broken chain. So
/// a crash on the wrong interpreter rendered as "The record of what happened
/// has been altered."
///
/// That is the most damaging bug this program can have. The one screen whose
/// entire purpose is honest tamper reporting was crying wolf, and an alarm that
/// fires when nothing is wrong is an alarm that gets ignored when something is.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainState {
    Intact,
    Broken,
    Unchecked,
}

#[derive(Serialize)]
pub struct ChainStatus {
    pub ok: bool,
    /// Retained: `checked == false` is exactly `state == Unchecked`. Kept so a
    /// caller that only asks "was a verdict reached?" cannot get it wrong.
    pub checked: bool,
    pub state: ChainState,
    /// What happened, in one sentence.
    pub detail: String,
    /// What to do about it, when there is something to do. Only ever set for
    /// `Unchecked`: a broken chain has no one-line remedy and offering one
    /// would be a lie.
    pub remedy: Option<String>,
    pub db_path: String,
}

impl ChainStatus {
    fn intact(detail: String, db_path: String) -> Self {
        Self { ok: true, checked: true, state: ChainState::Intact, detail, remedy: None, db_path }
    }
    fn broken(detail: String, db_path: String) -> Self {
        Self { ok: false, checked: true, state: ChainState::Broken, detail, remedy: None, db_path }
    }
    fn unchecked(detail: String, remedy: Option<String>, db_path: String) -> Self {
        Self { ok: false, checked: false, state: ChainState::Unchecked, detail, remedy, db_path }
    }
}

#[derive(Serialize)]
pub struct PendingApproval {
    pub prompt_id: i64,
    pub ts: f64,
    pub tool: String,
    pub rule_id: String,
    pub reason: String,
    pub paths: Vec<String>,
}

/// How many rows the Activity screen holds. The window shows a few; this is a
/// bound on memory, not a retention policy — audit.py keeps everything.
const RECENT_LIMIT: usize = 300;

/// Must agree with VERDICT_PREFIX in aegis/verify.py. A literal rather than
/// anything shared, because verify.py imports nothing and is imported by
/// nothing — that is the property that makes it worth trusting (S0 #4).
/// tests/bundle.py asserts the two strings match.
const VERDICT_PREFIX: &str = "AEGIS-VERIFY-VERDICT:";

/// Read-only, and provably so: SQLITE_OPEN_READ_ONLY makes any write attempt
/// fail at the SQLite layer rather than relying on this code never trying one.
fn open_ro(db: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("Cannot open {}: {e}", db.display()))
}

fn parse_paths(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

fn start_of_today() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    // Local midnight, derived from the machine's UTC offset.
    let offset = local_utc_offset_secs();
    let local = now + offset;
    let midnight_local = local - local.rem_euclid(86_400);
    (midnight_local - offset) as f64
}

/// Tauri pulls in no timezone crate; this asks the OS once per call.
fn local_utc_offset_secs() -> i64 {
    use std::process::Command;
    Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            let s = s.trim();
            if s.len() < 5 {
                return None;
            }
            let sign = if s.starts_with('-') { -1 } else { 1 };
            let h: i64 = s[1..3].parse().ok()?;
            let m: i64 = s[3..5].parse().ok()?;
            Some(sign * (h * 3600 + m * 60))
        })
        .unwrap_or(0)
}

pub fn read(
    db: &Path,
) -> Result<(Counters, Vec<AuditRow>, Option<PendingApproval>, Option<f64>), String> {
    if !db.exists() {
        return Err(format!(
            "There is no audit log at {}. Aegis has not run yet, or it is configured elsewhere.",
            db.display()
        ));
    }
    let conn = open_ro(db)?;
    let today = start_of_today();

    let mut stmt = conn
        .prepare(
            "SELECT id, ts, tool, effect, rule_id, reason, paths
             FROM audit ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows: Vec<AuditRow> = stmt
        .query_map([RECENT_LIMIT as i64], |r| {
            Ok(AuditRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                tool: r.get(2)?,
                effect: r.get(3)?,
                rule_id: r.get(4)?,
                reason: r.get(5)?,
                paths: parse_paths(&r.get::<_, String>(6)?),
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();

    let count = |sql: &str, p: [f64; 1]| -> i64 {
        conn.query_row(sql, p, |r| r.get(0)).unwrap_or(0)
    };
    let actions_today = count(
        "SELECT count(*) FROM audit WHERE ts >= ?1 AND effect = 'allow'",
        [today],
    );
    let blocked_today = count(
        "SELECT count(*) FROM audit WHERE ts >= ?1 AND effect = 'deny'",
        [today],
    );

    // A prompt is waiting when an approval_prompt row has no later row for the
    // same tool resolving it. The resolution rule_ids are exactly the ones
    // approval.py can produce.
    let pending = find_pending(&conn);
    let waiting = if pending.is_some() { 1 } else { 0 };

    let running_since: Option<f64> = conn
        .query_row("SELECT min(ts) FROM audit WHERE ts >= ?1", [today], |r| r.get(0))
        .ok()
        .flatten();

    Ok((
        Counters { actions_today, waiting, blocked_today },
        rows,
        pending,
        running_since,
    ))
}

fn find_pending(conn: &Connection) -> Option<PendingApproval> {
    let mut stmt = conn
        .prepare(
            "SELECT id, ts, tool, rule_id, reason, paths FROM audit
             WHERE rule_id = 'approval_prompt' ORDER BY id DESC LIMIT 1",
        )
        .ok()?;
    let row = stmt
        .query_row([], |r| {
            Ok(PendingApproval {
                prompt_id: r.get(0)?,
                ts: r.get(1)?,
                tool: r.get(2)?,
                rule_id: r.get(3)?,
                reason: r.get(4)?,
                paths: parse_paths(&r.get::<_, String>(5)?),
            })
        })
        .ok()?;

    // Resolved if any later row settles it. proxy.py always writes one
    // immediately after the prompt row, so an unresolved prompt means the
    // proxy is still blocked on a human right now.
    let resolved: i64 = conn
        .query_row(
            "SELECT count(*) FROM audit WHERE id > ?1 AND rule_id IN
             ('approval_granted','approval_denied','approval_timeout','ask_no_tty','audit_fail_closed')",
            [row.prompt_id],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if resolved > 0 {
        None
    } else {
        Some(row)
    }
}

/// Ask aegis/verify.py. The UI deliberately does not reimplement the hash
/// rule: verify.py is the authority (S2), it already carries an independent
/// second copy of the rule, and a third would be a third thing to keep in
/// agreement.
///
/// What this function must get right is not the hash — it is the difference
/// between an answer and no answer. Three things can stop the verifier before
/// it reaches a verdict, and all three used to look like tampering:
///
///   * no Python new enough to run it (the reported bug: a Finder-launched app
///     sees only `/usr/bin/python3`, which is 3.9, and Aegis needs 3.10),
///   * no Python at all, or a verifier that cannot be found,
///   * a verifier that started and then died.
///
/// So the verdict is read from verify.py's `--verdict` marker, which it prints
/// only after its check has returned. No marker means no verdict, and no
/// verdict is reported as `Unchecked` — never as `Broken`.
pub fn verify_chain(db: &Path, root: Option<&crate::locate::AegisRoot>) -> ChainStatus {
    let db_path = db.display().to_string();

    let verifier = match root {
        Some(r) => r.verifier(),
        None => {
            return ChainStatus::unchecked(
                // Never "assume intact": a viewer that cannot check the chain
                // must keep saying so.
                crate::locate::not_found_message(),
                None,
                db_path,
            );
        }
    };

    let python = match crate::python::find() {
        Ok(p) => p,
        Err(_) => {
            let search = crate::python::search();
            return ChainStatus::unchecked(
                crate::python::not_found_summary(&search.rejected),
                Some(crate::python::not_found_remedy()),
                db_path,
            );
        }
    };

    let output = python
        .command()
        .arg(&verifier)
        .arg(db)
        .arg("--verdict")
        .output();

    let out = match output {
        Ok(out) => out,
        Err(e) => {
            return ChainStatus::unchecked(
                format!(
                    "Aegis could not start the chain checker ({} at {}): {e}",
                    python.version_string(),
                    python.path.display()
                ),
                Some(crate::python::not_found_remedy()),
                db_path,
            )
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let verdict = stdout
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(VERDICT_PREFIX))
        .map(|v| v.trim().to_string());
    let human = |fallback: &str| -> String {
        let body = stdout
            .lines()
            .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with(VERDICT_PREFIX))
            .unwrap_or("")
            .trim()
            .to_string();
        if !stderr.is_empty() {
            stderr.clone()
        } else if !body.is_empty() {
            body
        } else {
            fallback.to_string()
        }
    };

    match verdict.as_deref() {
        Some("intact") => ChainStatus::intact(human("Chain intact."), db_path),
        Some("broken") => ChainStatus::broken(human("The audit chain does not verify."), db_path),
        Some("unreadable") => ChainStatus::unchecked(
            format!("The chain checker could not read the log: {}", human("no detail given")),
            None,
            db_path,
        ),
        // No marker, or one this build does not recognise. The checker never
        // reached a verdict, and the exit code cannot tell us more than that:
        // 1 is equally "chain broken" and "died with a traceback". Report the
        // only thing that is true — nothing was checked — and show what it did
        // print, because that is the whole clue to why.
        _ => ChainStatus::unchecked(
            format!(
                "The chain checker did not finish (exit {}). Nothing was checked, \
                 so this says nothing about your log.",
                out.status.code().unwrap_or(-1)
            ),
            // The machine's own words go HERE, not in the sentence above. A
            // traceback is not a message: the reported bug put one where the
            // explanation belongs, and a person reading it learned nothing they
            // could act on. It is still worth showing — it is the only clue to
            // why — so it goes in the secondary line, quoted, next to the
            // command that reproduces the whole thing.
            Some(format!(
                "It reported: {}. Aegis ran Python {} at {}. To see all of it: \
                 {} {} {}",
                first_useful_line(&stderr, &stdout),
                python.version_string(),
                python.path.display(),
                python.path.display(),
                verifier.display(),
                db.display()
            )),
            db_path,
        ),
    }
}

/// The first line worth showing a person out of a crash. A Python traceback
/// starts with "Traceback (most recent call last):" and the sentence that
/// matters is the last line; anything else reads better from the top.
fn first_useful_line(stderr: &str, stdout: &str) -> String {
    let text = if stderr.trim().is_empty() { stdout } else { stderr };
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return "It printed nothing.".to_string();
    }
    if lines[0].starts_with("Traceback (most recent call last)") {
        return (*lines.last().unwrap()).to_string();
    }
    lines[0].to_string()
}
