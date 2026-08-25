/** Browser-only layout harness.
 *
 *  This exists so the four screens can be checked against
 *  design/Aegis.dc.html without a Rust toolchain. It is imported dynamically
 *  and only when window.__TAURI_INTERNALS__ is absent, so it cannot be reached
 *  from the packaged app. Every snapshot it returns sets sample_data, and the
 *  app paints an unmissable banner when that flag is set.
 *
 *  The rows below are shaped exactly like real audit rows — same effects, same
 *  rule_ids, same reason strings that aegis/*.py actually writes — so what the
 *  harness renders is what the translation layer will do with real data.
 */

import type { Snapshot } from "./types";

const now = Math.floor(Date.now() / 1000);
const at = (h: number, m: number) => {
  const d = new Date();
  d.setHours(h, m, 0, 0);
  return Math.floor(d.getTime() / 1000);
};

export function sampleSnapshot(): Snapshot {
  return {
    sample_data: true,
    chain: {
      ok: true, checked: true, state: "intact",
      detail: "OK: 41 row(s) verified, chain intact",
      remedy: null, db_path: "(sample)",
    },
    counters: { actions_today: 128, waiting: 1, blocked_today: 2 },
    policy: {
      tools: ["read_file", "write_file", "edit_file", "move_file", "fetch", "delete_file"],
      workspace_roots: ["/Users/adarsh/Documents", "/Users/adarsh/Projects", "/Users/adarsh/Desktop"],
      deny_paths: [".env", "**/.aws/**", "**/.ssh/**", "*.pem"],
      allowed_domains: ["api.example.com"],
      credentials: ["github_token"],
      policy_path: "(sample)",
      loaded: true,
      error: null,
    },
    running_since: at(8, 2),
    pending: {
      prompt_id: 41,
      ts: at(15, 54),
      tool: "read_file",
      rule_id: "tool_rules.read_file",
      reason: "policy marks this tool as requiring human approval",
      paths: [
        "/Users/adarsh/Finance/q3-invoices.numbers",
        "/Users/adarsh/Finance/q4-invoices.numbers",
        "/Users/adarsh/Finance/vat-return.pdf",
        "/Users/adarsh/Finance/ledger.csv",
      ],
    },
    recent: [
      {
        id: 42, ts: at(16, 12), tool: "read_file", effect: "allow",
        rule_id: "tool_rules.read_file", reason: "matched allow rule",
        paths: Array.from({ length: 8 }, (_, i) => `/Users/adarsh/Projects/Atlas/src/f${i}.ts`),
      },
      {
        id: 41, ts: at(16, 9), tool: "read_file", effect: "deny",
        rule_id: "deny_paths", reason: "path matches deny rule '.env'",
        paths: ["/Users/adarsh/Projects/Atlas/.env"],
      },
      {
        id: 40, ts: at(15, 54), tool: "read_file", effect: "ask",
        rule_id: "approval_prompt",
        reason: "blocking for human approval (tool_rules.read_file)",
        paths: ["/Users/adarsh/Finance/q3-invoices.numbers", "/Users/adarsh/Finance/ledger.csv"],
      },
      {
        id: 39, ts: at(15, 31), tool: "edit_file", effect: "allow",
        rule_id: "tool_rules.edit_file",
        reason: "matched allow rule; 3 path(s) copied to trash as 20260816-153100",
        paths: [
          "/Users/adarsh/Projects/Atlas/a.ts",
          "/Users/adarsh/Projects/Atlas/b.ts",
          "/Users/adarsh/Projects/Atlas/c.ts",
        ],
      },
      {
        id: 38, ts: at(14, 47), tool: "fetch", effect: "allow",
        rule_id: "tool_rules.fetch",
        reason: "matched allow rule; substituted credential handle(s) github_token",
        paths: [],
      },
      {
        id: 37, ts: at(13, 20), tool: "fetch", effect: "deny",
        rule_id: "egress_domain",
        reason: "URL https://evil.xyz in arguments.url: host is not in allowed_domains",
        paths: [],
      },
      {
        id: 36, ts: at(12, 4), tool: "write_file", effect: "deny",
        rule_id: "dlp",
        reason: "argument arguments.content contains a value matching secret pattern 'aws_access_key_id'; the value is deliberately not recorded",
        paths: ["/Users/adarsh/Projects/Atlas/deploy.sh"],
      },
      {
        id: 35, ts: at(11, 15), tool: "fetch", effect: "redact",
        rule_id: "credential_redacted",
        reason: "server response echoed credential handle(s) github_token (1 occurrence(s))",
        paths: [],
      },
      {
        id: 34, ts: at(9, 58), tool: "list_directory", effect: "allow",
        rule_id: "tool_rules.list_directory", reason: "matched allow rule",
        paths: ["/Users/adarsh/Projects/Atlas"],
      },
      {
        id: 33, ts: now - 60 * 60 * 20, tool: "read_file", effect: "allow",
        rule_id: "tool_rules.read_file", reason: "matched allow rule",
        paths: ["/Users/adarsh/Documents/notes.md"],
      },
    ],
  };
}


/** Browser-harness permissions. Same banner rules as sampleSnapshot: this is
 *  never reachable from the packaged binary, and the app paints a warning when
 *  it is in use. It exists to check the layout, not to stand in for policy. */
export function samplePermissions() {
  return {
    policy_path: "/sample/policy.json",
    folders: [
      {
        path: "/Users/sample/Robotics",
        name: "Robotics",
        effect: "allow" as const,
        label: "Allow",
        sentence: "Can read and change your Robotics folder",
      },
      {
        path: "/Users/sample/Taxes",
        name: "Taxes",
        effect: "ask" as const,
        label: "Ask",
        sentence: "Must ask you first before touching your Taxes folder",
      },
      {
        path: "/Users/sample/Private",
        name: "Private",
        effect: "deny" as const,
        label: "Deny",
        sentence: "Cannot open your Private folder at all",
      },
    ],
    deny_paths: [
      { pattern: ".env", sentence: "Never open anything matching .env, in any folder" },
      { pattern: "id_rsa", sentence: "Never open anything matching id_rsa, in any folder" },
    ],
    editable: true,
    not_editable_reason: "",
    applies_note:
      "Changes apply the NEXT time your agent starts. A proxy that is already running read the policy once, when it launched, and is still enforcing that copy.",
  };
}
