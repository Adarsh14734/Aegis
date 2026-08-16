// Aegis S6 desktop viewer — Tauri backend.
//
// This process is a READER. It opens audit.db with SQLite's read-only URI flag
// and holds no write handle at any point. audit.py is the single writer; a
// second one would break the chain's single-writer assumption and, worse,
// would make a broken chain ambiguous between tampering and a race.
//
// The one thing that is not a read is resolve_approval, which forwards a
// human's answer to the approval bridge. It still does not touch the database:
// the proxy writes the resulting rows itself, through approval.py, exactly as
// if the answer had been typed at its terminal.

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
    bridge: BridgeStatus,
    running_since: Option<f64>,
}

#[derive(Serialize, Clone)]
pub struct BridgeStatus {
    available: bool,
    detail: String,
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

/// The bridge socket sits beside the database, created by
/// ui/bridge/aegis-approval-bridge.py when it is running.
fn bridge_socket() -> PathBuf {
    db_path().parent().unwrap_or(&dirs_home()).join("approval.sock")
}

fn bridge_status() -> BridgeStatus {
    let sock = bridge_socket();
    if !sock.exists() {
        return BridgeStatus {
            available: false,
            detail: "No approval bridge is running, so this window has no way to reach the agent."
                .into(),
        };
    }
    match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(_) => BridgeStatus { available: true, detail: String::new() },
        Err(e) => BridgeStatus {
            available: false,
            detail: format!("The approval bridge is not answering ({e})."),
        },
    }
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
        bridge: bridge_status(),
        running_since,
    })
}

#[tauri::command]
fn resolve_approval(prompt_id: i64, approve: bool) -> Result<String, String> {
    use std::io::{Read, Write};
    let sock = bridge_socket();
    let mut stream = std::os::unix::net::UnixStream::connect(&sock)
        .map_err(|e| format!("Could not reach the approval bridge: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    // The wire format is deliberately two fields and nothing else. The bridge
    // types "y" or "n" on the proxy's terminal; it cannot be asked to run a
    // command, name a file, or answer a different request than the one shown.
    let msg = format!("{{\"prompt_id\":{prompt_id},\"answer\":\"{}\"}}\n", if approve { "y" } else { "n" });
    stream.write_all(msg.as_bytes()).map_err(|e| e.to_string())?;

    let mut reply = String::new();
    stream.read_to_string(&mut reply).map_err(|e| e.to_string())?;
    let reply = reply.trim().to_string();
    if reply.is_empty() {
        return Err("The approval bridge closed without answering.".into());
    }
    Ok(reply)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![snapshot, resolve_approval])
        .run(tauri::generate_context!())
        .expect("error while running Aegis");
}
