//! Read-only view of policy.json. Never written, never rewritten.

use serde::Serialize;
use std::path::Path;

#[derive(Serialize, Default)]
pub struct PolicyView {
    pub tools: Vec<String>,
    pub workspace_roots: Vec<String>,
    pub deny_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub credentials: Vec<String>,
    pub policy_path: String,
    pub loaded: bool,
    pub error: Option<String>,
}

fn strings(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn keys(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|x| x.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn read(path: &Path) -> PolicyView {
    let mut out = PolicyView { policy_path: path.display().to_string(), ..Default::default() };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            out.error = Some(format!("could not be read ({e})"));
            return out;
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(e) => {
            out.error = Some(format!("is not valid JSON ({e})"));
            return out;
        }
    };
    out.tools = keys(doc.get("tool_rules"));
    out.workspace_roots = strings(doc.get("workspace_roots"));
    out.deny_paths = strings(doc.get("deny_paths"));
    out.allowed_domains = strings(doc.get("allowed_domains"));
    out.credentials = keys(doc.get("credentials"));
    out.loaded = true;
    out
}
