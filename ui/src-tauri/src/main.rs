// Aegis S6 desktop viewer — Tauri backend.
//
// This process is a READER. It opens audit.db with SQLite's read-only URI flag
// and holds no write handle at any point. audit.py is the single writer; a
// second one would break the chain's single-writer assumption and, worse,
// would make a broken chain ambiguous between tampering and a race.
//
// S10 adds the FIRST commands that change anything: the Permissions screen can
// edit policy.json. They live in permissions.rs and decide nothing themselves —
// every gate (chain must verify, the proxy's own loader must accept the
// document, widening must be confirmed, atomic 0600 write) is in
// aegis/policyedit.py, where it is tested and where it applies equally to a
// terminal. audit.db is still opened read-only and audit.py is still its only
// writer.
//
// An earlier revision carried a resolve_approval command that forwarded a
// human's answer to an approval bridge; the bridge was removed rather than
// shipped unverified (S6-REPORT.md) and the command went with it. Approvals are
// answered at the proxy's terminal.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;
mod locate;
mod permissions;
mod policy;
mod python;

use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct Snapshot {
    chain: audit::ChainStatus,
    counters: audit::Counters,
    policy: policy::PolicyView,
    recent: Vec<audit::AuditRow>,
    pending: Option<audit::PendingApproval>,
    running_since: Option<f64>,
}

/// Where audit.db lives. Mirrors aegis/audit.py::default_db_path, including
/// the AEGIS_AUDIT_DB override so the UI follows a test or alternate install.
fn db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_AUDIT_DB") {
        return PathBuf::from(p);
    }
    let home = dirs_home();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Aegis/audit.db")
    } else {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local/share"))
            .join("aegis/audit.db")
    }
}

/// Mirrors aegis/proxy.py::default_policy_path.
fn policy_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_POLICY") {
        return PathBuf::from(p);
    }
    let home = dirs_home();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Aegis/policy.json")
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".config"))
            .join("aegis/policy.json")
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"))
}

#[tauri::command]
fn snapshot(app: tauri::AppHandle) -> Result<Snapshot, String> {
    let db = db_path();
    // The locator is asked once and shared: the verifier and the policy editor
    // must agree about which Aegis they are talking to.
    let root = locate::find(Some(&app));
    let chain = audit::verify_chain(&db, root.as_ref());
    // Rows are read even when the chain is broken: hiding them would destroy
    // the operator's only view of what happened. The UI labels them instead.
    let (counters, recent, pending, running_since) = audit::read(&db)?;
    Ok(Snapshot {
        chain,
        counters,
        policy: policy::read(&policy_path()),
        recent,
        pending,
        running_since,
    })
}

/// Three flags that ask this binary a question and exit without a window.
///
/// They exist so the SHIPPED artifact can be tested in its installed shape. The
/// bugs this sprint fixed were all invisible to every existing test because the
/// tests ran in the development tree, from a terminal, against a repository
/// that sits above the executable — and none of those three things is true of
/// `/Applications/Aegis.app` launched from the Dock. A GUI cannot be asserted
/// on headlessly, so each decision that broke gets a way to be asked directly.
///
/// All three read; none of them change anything.
///
///   --locate   where this binary would find the Python side
///   --python   which interpreter it would run, and whether it is new enough
///   --chain    what it would tell the user about the audit chain right now
fn cli_and_exit() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);

    if has("--locate") {
        match locate::find(None) {
            Some(root) => println!(
                "{}",
                serde_json::json!({
                    "found": true,
                    "dir": root.dir.display().to_string(),
                    "source": root.source,
                    "verifier": root.verifier().display().to_string(),
                })
            ),
            None => println!(
                "{}",
                serde_json::json!({"found": false, "message": locate::not_found_message()})
            ),
        }
        return true;
    }

    if has("--python") {
        let search = python::search();
        // The rejected list is reported too. "No Python found" and "a Python
        // was found and it is too old" send a user to different places, and
        // only the second one can name the version they have.
        let rejected: Vec<serde_json::Value> = search
            .rejected
            .iter()
            .map(|r| {
                serde_json::json!({
                    "path": r.path,
                    "version": format!("{}.{}.{}", r.version.0, r.version.1, r.version.2),
                })
            })
            .collect();
        println!(
            "{}",
            match &search.found {
                Some(i) => serde_json::json!({
                    "found": true,
                    "path": i.path.display().to_string(),
                    "version": i.version_string(),
                    "source": i.source,
                    "minimum": python::required(),
                    "rejected": rejected,
                }),
                None => serde_json::json!({
                    "found": false,
                    "minimum": python::required(),
                    "message": python::not_found_message(&search.rejected),
                    "rejected": rejected,
                }),
            }
        );
        return true;
    }

    if has("--chain") {
        // Exactly what the banner at the top of the window is built from,
        // including the state that decides which banner it is. This is the
        // check that used to render a crashed verifier as a tampered log.
        let db = db_path();
        let root = locate::find(None);
        let status = audit::verify_chain(&db, root.as_ref());
        println!("{}", serde_json::to_string(&status).unwrap_or_default());
        return true;
    }

    false
}

fn main() {
    if cli_and_exit() {
        return;
    }
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            snapshot,
            permissions::permissions,
            permissions::set_folder,
            permissions::set_deny
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aegis");
}
