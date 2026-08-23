//! Aegis S10 — the only write path in this application.
//!
//! Everything else in this process is a reader (see main.rs). This module
//! changes policy.json, which THREAT-MODEL.md A7 calls the asset that, if
//! compromised, makes every other control decorative. So it is deliberately
//! thin: it decides nothing.
//!
//! It shells out to `aegis policy`, which is `aegis/policyedit.py`. That is the
//! same choice audit.rs made for `verify.py`, for the same reason and one more:
//!
//!   - **One implementation.** The validation that matters is "would the proxy
//!     reject this?", and the only truthful way to answer it is to call the
//!     proxy's own loader. A Rust reimplementation of policy.py's rules would be
//!     a second decision engine that can drift from the first, and the drift
//!     would show up as the UI permitting something the proxy refuses — or
//!     worse, the reverse.
//!   - **It can be tested.** The Python path is exercised by tests/s10.py on
//!     real files. Rust here would be logic whose only coverage is a screenshot.
//!
//! So the gates — chain must verify, document must load, widening must be
//! confirmed, write atomically at 0600 — all live in Python and all apply
//! whether the call came from this window or from a terminal. This file cannot
//! skip them, because it does not implement them.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize, Debug)]
pub struct EditResult {
    #[serde(default)]
    pub written: bool,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub changes: Vec<String>,
    #[serde(default)]
    pub granted: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Locate the repository root that holds `aegis/`.
///
/// Same search-don't-guess approach as audit.rs::find_verifier, and the same
/// reason: `cargo run`, `tauri dev` and a bundled .app each nest the binary
/// differently, so any fixed depth is wrong for at least one of them.
fn find_aegis_root() -> Option<PathBuf> {
    fn holds(dir: &Path) -> Option<PathBuf> {
        dir.join("aegis").join("policyedit.py").is_file().then(|| dir.to_path_buf())
    }
    if let Ok(home) = std::env::var("AEGIS_HOME") {
        if let Some(found) = holds(Path::new(&home)) {
            return Some(found);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(found) = exe.ancestors().find_map(holds) {
            return Some(found);
        }
    }
    std::env::current_dir().ok().and_then(|cwd| cwd.ancestors().find_map(holds))
}

fn run_policy_command(args: &[&str]) -> Result<String, String> {
    let root = find_aegis_root().ok_or_else(|| {
        "Aegis could not find its own installation, so nothing was changed. \
         Set AEGIS_HOME to the directory containing aegis/."
            .to_string()
    })?;

    let output = Command::new("python3")
        .arg("-m")
        .arg("aegis.cli")
        .arg("policy")
        .args(args)
        .current_dir(&root)
        .env("PYTHONPATH", &root)
        .output()
        .map_err(|e| format!("could not run the Aegis policy editor: {e}"))?;

    if output.stdout.is_empty() && !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Everything the Permissions screen shows. Read-only.
#[tauri::command]
pub fn permissions() -> Result<serde_json::Value, String> {
    let out = run_policy_command(&["show"])?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable permissions: {e}"))
}

/// Set one folder to allow / ask / deny.
///
/// `confirm_grant` is passed through, never assumed. The UI must have shown the
/// user what is being granted before it sets this, and Python refuses the write
/// without it — so a bug in this file's callers fails closed rather than
/// silently widening.
#[tauri::command]
pub fn set_folder(path: String, effect: String, confirm_grant: bool) -> Result<EditResult, String> {
    let mut args = vec!["set-folder", path.as_str(), effect.as_str(), "--json"];
    if confirm_grant {
        args.push("--confirm-grant");
    }
    let out = run_policy_command(&args)?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable result: {e}"))
}

/// Add or remove a deny-list entry. Removing one is widening and needs confirm.
#[tauri::command]
pub fn set_deny(pattern: String, blocked: bool, confirm_grant: bool) -> Result<EditResult, String> {
    let action = if blocked { "deny-add" } else { "deny-remove" };
    let mut args = vec![action, pattern.as_str(), "--json"];
    if confirm_grant {
        args.push("--confirm-grant");
    }
    let out = run_policy_command(&args)?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable result: {e}"))
}
