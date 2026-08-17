// Aegis S6 desktop viewer — Tauri backend.
//
// This process is a READER. It opens audit.db with SQLite's read-only URI flag
// and holds no write handle at any point. audit.py is the single writer; a
// second one would break the chain's single-writer assumption and, worse,
// would make a broken chain ambiguous between tampering and a race.
//
// There is no command that changes anything. An earlier revision carried a
// resolve_approval command that forwarded a human's answer to an approval
// bridge; the bridge was removed rather than shipped unverified (S6-REPORT.md)
// and the command went with it. Approvals are answered at the proxy's terminal.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;
mod policy;

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
fn snapshot() -> Result<Snapshot, String> {
    let db = db_path();
    let chain = audit::verify_chain(&db);
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![snapshot])
        .run(tauri::generate_context!())
        .expect("error while running Aegis");
}
