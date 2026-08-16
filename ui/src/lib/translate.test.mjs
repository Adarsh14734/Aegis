/** Tests for the plain-English layer.
 *
 *  Run with: npm test  (compiles translate.ts first — see scripts/build-test.mjs)
 *
 *  The rules being tested are the two the brief cares about: a rule_id never
 *  reaches the screen, and nothing is claimed that the audit row does not say.
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  activityLine,
  approvalHeadline,
  approvalWhy,
  chainDetailSummary,
  describeFiles,
  statusSentence,
  whyBlocked,
} from "../../.test-build/lib/translate.js";

const row = (o) => ({
  id: 1, ts: 1_700_000_000, tool: "read_file", effect: "allow",
  rule_id: "tool_rules.read_file", reason: "matched allow rule", paths: [], ...o,
});

/** Every rule_id audit.py can write, and the sentence it must not produce. */
const ALL_RULE_IDS = [
  "killswitch", "deny_paths", "dlp", "egress_domain", "credential_denied",
  "credential_unavailable", "bulk_operation", "ask_no_tty", "approval_timeout",
  "approval_denied", "trash_failed", "trash_unavailable", "scan_limit",
  "malformed", "fail_closed", "audit_fail_closed", "default_effect",
  "tool_rules.delete_file", "tool_rules.write_file.within",
];

test("no rule_id ever reaches the screen", () => {
  for (const rule_id of ALL_RULE_IDS) {
    const { text } = activityLine(row({ effect: "deny", rule_id, paths: ["/Users/x/a.txt"] }));
    assert.ok(!text.includes(rule_id), `${rule_id} leaked into: ${text}`);
    assert.ok(!/_/.test(text), `snake_case leaked into: ${text}`);
    assert.ok(text.length > 20, `too terse for ${rule_id}: ${text}`);
  }
});

test("deny_paths names the kind of file, not the rule", () => {
  assert.match(whyBlocked({ rule_id: "deny_paths", reason: "", paths: ["/Users/x/p/.env"] }),
    /passwords and keys/);
  assert.match(whyBlocked({ rule_id: "deny_paths", reason: "", paths: ["/Users/x/.aws/credentials"] }),
    /cloud credentials/);
  assert.match(whyBlocked({ rule_id: "deny_paths", reason: "", paths: ["/Users/x/.ssh/id_rsa"] }),
    /SSH keys/);
  assert.match(whyBlocked({ rule_id: "deny_paths", reason: "", paths: ["/Users/x/k.pem"] }),
    /private key/);
});

test("blocked rows read as blocked", () => {
  const { text, kind } = activityLine(
    row({ effect: "deny", rule_id: "deny_paths", paths: ["/Users/x/.env"] }));
  assert.equal(kind, "blocked");
  assert.match(text, /^Aegis stopped/);
});

test("waiting rows are marked waiting, not blocked", () => {
  const { kind } = activityLine(row({ effect: "ask", rule_id: "approval_prompt" }));
  assert.equal(kind, "waiting");
});

test("file counts are described, never invented", () => {
  assert.equal(describeFiles([]), "");
  assert.equal(describeFiles(["/a/b.txt"]), "b.txt");
  assert.equal(describeFiles(["/a/b.txt", "/a/c.txt"]), "b.txt and 1 other");
  assert.equal(describeFiles(["/a/1", "/a/2", "/a/3"]), "3 files");
});

test("home directory is abbreviated in folder names", () => {
  const { text } = activityLine(row({
    paths: ["/Users/adarsh/Projects/Atlas/a.ts", "/Users/adarsh/Projects/Atlas/b.ts"],
  }));
  assert.match(text, /~\/Projects\/Atlas/);
  assert.ok(!text.includes("/Users/adarsh"), text);
});

test("the status sentence matches the counters and claims nothing else", () => {
  assert.match(statusSentence({ waiting: 1, blocked_today: 0, actions_today: 5 }), /One request is waiting/);
  assert.match(statusSentence({ waiting: 3, blocked_today: 0, actions_today: 5 }), /3 requests are waiting/);
  assert.match(statusSentence({ waiting: 0, blocked_today: 2, actions_today: 5 }), /stopped 2 things/);
  assert.match(statusSentence({ waiting: 0, blocked_today: 0, actions_today: 0 }), /Nothing has happened/);
});


test("credential substitution is reported without naming a value", () => {
  const { text } = activityLine(row({
    effect: "allow", tool: "fetch",
    reason: "matched allow rule; substituted credential handle(s) github_token",
  }));
  assert.match(text, /without ever seeing it/);
});

test("approval headline and reason come from the row", () => {
  const p = {
    prompt_id: 1, ts: 0, tool: "read_file", rule_id: "bulk_operation",
    reason: "call touches 14 paths, above the bulk threshold of 10",
    paths: Array.from({ length: 14 }, (_, i) => `/Users/x/Finance/f${i}.csv`),
  };
  assert.match(approvalHeadline(p), /^An agent wants to read 14 files in ~\/Finance$/);
  assert.match(approvalWhy(p), /14 of them/);
});

test("the chain banner shows the verifier's summary, not its hash dump", () => {
  const raw = [
    "FAIL: audit chain broken at row id 3",
    "  row_hash mismatch — row contents were altered",
    "  stored:     023bbe619c80d3449327e332a437e6b8aae7db56b786d9d4e8973988fae031a9",
    "  row: tool='read_file' effect='allow' rule_id='deny_paths'",
  ].join("\n");
  const out = chainDetailSummary(raw);
  assert.equal(out, "Audit chain broken at row id 3");
  assert.ok(!/rule_id|_hash|[0-9a-f]{32}/.test(out), out);
});

test("...even if the newlines were flattened to spaces upstream", () => {
  const flat = "FAIL: audit chain broken at row id 3   row_hash mismatch   stored: 023bbe619c80";
  assert.equal(chainDetailSummary(flat), "Audit chain broken at row id 3");
});
