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

#[derive(Serialize)]
pub struct ChainStatus {
    pub ok: bool,
    pub checked: bool,
    pub detail: String,
    pub db_path: String,
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

/// Locate `aegis/verify.py`.
///
/// The first version guessed a fixed depth above the executable
/// (`ancestors().nth(4)`), which pointed at `ui/aegis/verify.py` — a path that
/// does not exist. The verifier lives at the repo root. A fixed depth was
/// always going to be wrong for at least one of `cargo run`, `tauri dev` and a
/// bundled .app, since each nests the binary differently.
///
/// So: search instead of guess. AEGIS_HOME wins when it actually contains the
/// verifier — it is an operator override, the same shape as AEGIS_POLICY and
/// AEGIS_AUDIT_DB elsewhere — and a stale one is ignored rather than silently
/// used, because "the verifier is missing" and "the verifier is somewhere else"
/// should not look the same on screen. Otherwise walk up from the executable,
/// then from the working directory, which is what makes `tauri dev` work.
fn find_verifier() -> Option<std::path::PathBuf> {
    fn holds_verifier(dir: &Path) -> Option<std::path::PathBuf> {
        let candidate = dir.join("aegis").join("verify.py");
        candidate.is_file().then_some(candidate)
    }
    fn walk_up(start: &Path) -> Option<std::path::PathBuf> {
        start.ancestors().find_map(holds_verifier)
    }

    if let Ok(home) = std::env::var("AEGIS_HOME") {
        if let Some(found) = holds_verifier(Path::new(&home)) {
            return Some(found);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(found) = walk_up(&exe) {
            return Some(found);
        }
    }
    std::env::current_dir().ok().and_then(|cwd| walk_up(&cwd))
}

/// Ask aegis/verify.py. The UI deliberately does not reimplement the hash
/// rule: verify.py is the authority (S2), it already carries an independent
/// second copy of the rule, and a third would be a third thing to keep in
/// agreement. If the verifier cannot be run, that is reported as "not
/// checked" rather than silently treated as intact.
pub fn verify_chain(db: &Path) -> ChainStatus {
    let db_path = db.display().to_string();
    let verifier = match find_verifier() {
        Some(v) => v,
        None => {
            return ChainStatus {
                ok: false,
                checked: false,
                detail: format!(
                    "The chain verifier (aegis/verify.py) could not be found near {}. \
                     Set AEGIS_HOME to the Aegis directory.",
                    std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "this app".into())
                ),
                db_path,
            };
        }
    };
    match std::process::Command::new("python3")
        .arg(&verifier)
        .arg(db)
        .output()
    {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match code {
                0 => ChainStatus {
                    ok: true,
                    checked: true,
                    detail: stdout.lines().next().unwrap_or("Chain intact.").to_string(),
                    db_path,
                },
                1 => ChainStatus {
                    ok: false,
                    checked: true,
                    detail: if text.is_empty() { stdout } else { text },
                    db_path,
                },
                _ => ChainStatus {
                    ok: false,
                    checked: false,
                    detail: format!("The verifier could not read the log: {text}"),
                    db_path,
                },
            }
        }
        Err(e) => ChainStatus {
            ok: false,
            checked: false,
            detail: format!("Could not run the verifier: {e}"),
            db_path,
        },
    }
}
