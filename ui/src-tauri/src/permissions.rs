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

fn run_policy_command(app: &tauri::AppHandle, args: &[&str]) -> Result<String, String> {
    // Shared with the chain verifier: one place decides where the Python side
    // is, and it covers the installed .app before the dev tree. See locate.rs.
    let root = crate::locate::find(Some(app)).ok_or_else(|| {
        format!("{} Nothing was changed.", crate::locate::not_found_message())
    })?;

    // Not `python3`: an app launched from Finder has a PATH of
    // /usr/bin:/bin:/usr/sbin:/sbin, where python3 is the 3.9 Command Line
    // Tools shim. Aegis needs 3.10, so that interpreter died on an annotation
    // in cli.py and the Permissions screen showed the traceback. python.rs
    // picks an interpreter that can actually load the package, or says why not.
    let python = crate::python::find().map_err(|e| format!("{e} Nothing was changed."))?;

    let output = python
        .command()
        .arg("-m")
        .arg("aegis.cli")
        .arg("policy")
        .args(args)
        .current_dir(&root.dir)
        .env("PYTHONPATH", &root.dir)
        .output()
        .map_err(|e| format!("could not run the Aegis policy editor: {e}"))?;

    if output.stdout.is_empty() && !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Everything the Permissions screen shows. Read-only.
#[tauri::command]
pub fn permissions(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let out = run_policy_command(&app, &["show"])?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable permissions: {e}"))
}

/// Set one folder to allow / ask / deny.
///
/// `confirm_grant` is passed through, never assumed. The UI must have shown the
/// user what is being granted before it sets this, and Python refuses the write
/// without it — so a bug in this file's callers fails closed rather than
/// silently widening.
#[tauri::command]
pub fn set_folder(
    app: tauri::AppHandle,
    path: String,
    effect: String,
    confirm_grant: bool,
) -> Result<EditResult, String> {
    let mut args = vec!["set-folder", path.as_str(), effect.as_str(), "--json"];
    if confirm_grant {
        args.push("--confirm-grant");
    }
    let out = run_policy_command(&app, &args)?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable result: {e}"))
}

/// Add or remove a deny-list entry. Removing one is widening and needs confirm.
#[tauri::command]
pub fn set_deny(
    app: tauri::AppHandle,
    pattern: String,
    blocked: bool,
    confirm_grant: bool,
) -> Result<EditResult, String> {
    let action = if blocked { "deny-add" } else { "deny-remove" };
    let mut args = vec![action, pattern.as_str(), "--json"];
    if confirm_grant {
        args.push("--confirm-grant");
    }
    let out = run_policy_command(&app, &args)?;
    serde_json::from_str(&out).map_err(|e| format!("unreadable result: {e}"))
}
