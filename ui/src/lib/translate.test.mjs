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
  chainBanner,
  approvalHeadline,
  approvalWhy,
  chainDetailSummary,
  describeFiles,
  formatTime,
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

test("formatTime keeps a bare clock for today and dates anything older", () => {
  const now = new Date();
  const todayAfternoon = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 14, 5);
  assert.equal(formatTime(todayAfternoon.getTime() / 1000), "2:05 pm");

  const yesterday = new Date(todayAfternoon);
  yesterday.setDate(yesterday.getDate() - 1);
  assert.equal(formatTime(yesterday.getTime() / 1000), "Yesterday 2:05 pm");

  // The regression this test exists for: Activity fetches recent rows by id
  // with no date filter, so an older row used to render as a bare "2:05 pm"
  // and read as today — while Status, counting only since local midnight,
  // correctly reported nothing today. The screens appeared to disagree about
  // one database.
  const older = new Date(todayAfternoon);
  older.setDate(older.getDate() - 5);
  const rendered = formatTime(older.getTime() / 1000);
  assert.ok(
    !/^\d{1,2}:\d{2} (am|pm)$/.test(rendered),
    `a row from five days ago rendered as a bare time: ${rendered}`,
  );
  assert.match(rendered, /2:05 pm$/);
});


/* ---------------------------------------------------------------------------
 * A crashed verifier is not a tampered chain.
 *
 * The regression these exist for: the Rust side set `checked` from the
 * verifier's exit code, and a Python that could not run verify.py exits 1 —
 * the same code verify.py uses for a broken chain. So the banner on a machine
 * with the wrong interpreter read "The record of what happened has been
 * altered." Nothing had been altered and nothing had been checked.
 *
 * The screen whose entire purpose is honest tamper reporting must not cry
 * wolf, so these tests assert the two states never share words.
 * ------------------------------------------------------------------------- */

const chain = (o) => ({
  ok: false, checked: false, state: "unchecked",
  detail: "", remedy: "", db_path: "/tmp/audit.db", ...o,
});

test("an intact chain shows no banner at all", () => {
  const b = chainBanner(chain({
    ok: true, checked: true, state: "intact",
    detail: "OK: 41 row(s) verified, chain intact",
  }));
  assert.equal(b.tone, "none");
  assert.equal(b.headline, "");
});

test("a broken chain says the record was altered, and distrusts the rows", () => {
  const b = chainBanner(chain({
    state: "broken", checked: true,
    detail: "FAIL: audit chain broken at row id 3\n  row_hash mismatch",
  }));
  assert.equal(b.tone, "alarm");
  assert.match(b.headline, /has been altered/);
  assert.equal(b.distrustRows, true);
  // The hash dump stays off the screen — same rule as every other detail line.
  assert.ok(!b.body.includes("row_hash"), b.body);
});

test("a verifier that could not run NEVER says the record was altered", () => {
  const crashes = [
    // The reported one: 3.9 on the PATH a Finder-launched app inherits.
    "Aegis needs Python 3.10 or newer and did not find it. The newest on this " +
      "machine is Python 3.9.6, at /Library/Developer/CommandLineTools/usr/bin/python3.",
    // A verifier that started and died.
    "The chain checker did not finish (exit 1). Nothing was checked — this is " +
      "not a report about your log. TypeError: unsupported operand type(s) for |",
    // No Python side in the bundle at all.
    "Aegis could not find its own Python components.",
  ];
  for (const detail of crashes) {
    const b = chainBanner(chain({ state: "unchecked", detail }));
    assert.equal(b.tone, "caution", detail);
    assert.match(b.headline, /could not check/);
    // The accusation itself must never appear anywhere in the banner, and the
    // headline — the line people actually read — carries none of its words.
    assert.ok(!/has been altered|was altered|tamper/i.test(b.headline + " " + b.body),
      `a crashed verifier accused the log: ${b.headline} ${b.body}`);
    assert.ok(!/alter|tamper|broken/i.test(b.headline),
      `a crashed verifier accused the log in its headline: ${b.headline}`);
    assert.equal(b.distrustRows, false);
  }
});

test("...and it does not claim the log is fine either", () => {
  const b = chainBanner(chain({ state: "unchecked", detail: "no interpreter" }));
  assert.match(b.body, /nothing was checked/i);
  assert.ok(!/intact|verified|fine|ok\b/i.test(b.headline), b.headline);
});

test("the two states share no wording a person could confuse", () => {
  const broken = chainBanner(chain({ state: "broken", checked: true, detail: "FAIL: x" }));
  const unchecked = chainBanner(chain({ state: "unchecked", detail: "y" }));
  assert.notEqual(broken.headline, unchecked.headline);
  assert.notEqual(broken.tone, unchecked.tone);
});

test("a snapshot with no state at all falls back to 'no verdict', not 'broken'", () => {
  // Defensive: an older backend, or a field lost in transit. The safe reading
  // of a missing verdict is that there was no verdict.
  const b = chainBanner({ ok: false, checked: false, detail: "?", db_path: "" });
  assert.equal(b.tone, "caution");
  assert.equal(b.distrustRows, false);
});

test("the remedy is shown when there is one, and never invented", () => {
  const withFix = chainBanner(chain({
    state: "unchecked", detail: "no Python", remedy: "Install Python 3.10 or newer.",
  }));
  assert.match(withFix.remedy, /Install Python/);
  const noFix = chainBanner(chain({ state: "broken", checked: true, detail: "FAIL: x" }));
  assert.equal(noFix.remedy, "");
});
