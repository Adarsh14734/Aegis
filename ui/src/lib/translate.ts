/** Turning audit rows into ordinary language.
 *
 *  The brief: "deny_paths becomes 'opening your saved passwords file', not
 *  'deny_paths'". Everything here is a rendering of fields that are already in
 *  the row — tool, effect, rule_id, paths. Nothing is inferred about intent,
 *  and nothing is added that the audit database does not contain. Where a row
 *  does not say something, the sentence does not claim it.
 *
 *  Two rules this file follows:
 *    1. Never invent. If the reason column is empty, the sentence is shorter.
 *    2. Never soften a denial. A blocked row reads as blocked.
 */

import type { AuditRow, PendingApproval } from "../types";

export type RowKind = "plain" | "blocked" | "waiting";

const HOME = /^\/Users\/[^/]+/;

/** ~/Documents/notes.txt for display; the audit keeps the absolute path. */
export function shortPath(p: string): string {
  return p.replace(HOME, "~");
}

export function fileName(p: string): string {
  const parts = p.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : p;
}

/** "notes.txt", "notes.txt and 1 other", "4 files" */
export function describeFiles(paths: string[]): string {
  if (paths.length === 0) return "";
  if (paths.length === 1) return fileName(paths[0]);
  if (paths.length === 2) return `${fileName(paths[0])} and 1 other`;
  return `${paths.length} files`;
}

/** The folder a set of paths sits in, when they share one. */
export function commonFolder(paths: string[]): string | null {
  if (paths.length === 0) return null;
  const dirs = paths.map((p) => p.slice(0, p.lastIndexOf("/")));
  const first = dirs[0];
  return dirs.every((d) => d === first) ? shortPath(first) : null;
}

/** Verb for a tool name. Falls back to the tool's own name rather than
 *  guessing — an unknown tool is described, not characterised. */
export function toolVerb(tool: string): { present: string; past: string } {
  const t = tool.toLowerCase();
  if (t.includes("read") || t.includes("cat")) return { present: "read", past: "read" };
  if (t.includes("write") || t.includes("create")) return { present: "write to", past: "wrote" };
  if (t.includes("edit")) return { present: "change", past: "changed" };
  if (t.includes("move") || t.includes("rename")) return { present: "move", past: "moved" };
  if (t.includes("delete") || t.includes("remove") || t.includes("purge"))
    return { present: "delete", past: "deleted" };
  if (t.includes("list") || t.includes("directory") || t.includes("tree"))
    return { present: "list", past: "listed" };
  if (t.includes("search") || t.includes("grep")) return { present: "search", past: "searched" };
  if (t.includes("fetch") || t.includes("http") || t.includes("url") || t.includes("web"))
    return { present: "send a request to", past: "sent a request" };
  return { present: "use a tool", past: "used a tool" };
}

/** What the *denial* was about, in the user's terms. This is the table the
 *  brief is really about: a rule_id is an engineering label, and the person
 *  reading this screen did not write the policy. */
export function whyBlocked(row: { rule_id: string; reason: string; paths: string[] }): string {
  const rule = row.rule_id;
  const files = describeFiles(row.paths);
  const named = files ? ` ${files}` : "";

  if (rule === "deny_paths") {
    const p = row.paths[0] ?? "";
    const n = fileName(p).toLowerCase();
    if (n === ".env" || n.endsWith(".env")) return "opening a file that holds your passwords and keys";
    if (p.includes("/.aws/")) return "opening your saved cloud credentials";
    if (p.includes("/.ssh/") || n.startsWith("id_rsa")) return "opening your SSH keys";
    if (n.endsWith(".pem")) return "opening a private key file";
    return `opening${named || " a file"} you told Aegis to keep private`;
  }
  if (rule === "dlp") return "putting a password or key into a file it was writing";
  if (rule === "egress_domain") return "sending something to a website that is not on your list";
  if (rule === "credential_denied") return "using one of your saved logins somewhere it is not allowed";
  if (rule === "credential_unavailable") return "using a saved login that Aegis could not find";
  if (rule === "killswitch") return "doing anything at all, because you pressed stop";
  if (rule === "bulk_operation") return `touching${named || " a lot of files"} at once`;
  if (rule === "ask_no_tty") return "going ahead without asking you, when nobody was there to ask";
  if (rule === "approval_timeout") return "going ahead when the request was not answered in time";
  if (rule === "approval_denied") return "going ahead after you said no";
  if (rule === "trash_failed") return "deleting something Aegis could not make a copy of first";
  if (rule === "trash_unavailable") return "deleting something with nowhere to keep a copy";
  if (rule === "malformed" || rule === "fail_closed" || rule === "scan_limit")
    return "a request Aegis could not read properly";
  if (rule === "audit_fail_closed") return "acting while Aegis could not write to its own record";
  if (rule === "default_effect") return "using a tool you have not allowed";
  if (rule.endsWith(".within")) return `reaching outside the folders you allow`;
  if (rule.startsWith("tool_rules.")) return "using a tool you have blocked";
  return "an action your rules do not allow";
}

/** One row of the Activity screen. */
/** The audit database records which *tool* ran, never which agent called it —
 *  one proxy sits in front of one MCP server and no client identity crosses
 *  the wire. So the sentences say "an agent". Naming a product here would be
 *  inventing a fact the log does not contain, and printing the raw tool name
 *  ("read_file wants to read four files") is the same snake_case jargon the
 *  rule_id translation exists to remove. The verb still comes from the tool,
 *  so what happened is not lost. */
const ACTOR = "an agent";
const Actor = "An agent";

export function activityLine(row: AuditRow): { text: string; kind: RowKind } {
  const files = describeFiles(row.paths);
  const folder = commonFolder(row.paths);
  const where = folder ? ` in ${folder}` : "";
  const verb = toolVerb(row.tool);

  if (row.effect === "deny") {
    return { text: `Aegis stopped ${ACTOR} from ${whyBlocked(row)}.`, kind: "blocked" };
  }
  if (row.effect === "ask") {
    const what = files ? `${verb.present} ${files}${where}` : verb.present;
    return { text: `${Actor} asked to ${what}. Still waiting for you.`, kind: "waiting" };
  }
  if (row.effect === "redact") {
    return {
      text: `Aegis removed one of your saved logins from a reply before ${ACTOR} could see it.`,
      kind: "plain",
    };
  }
  // allow
  if (row.reason.includes("substituted credential handle")) {
    return { text: `${Actor} used one of your saved logins without ever seeing it.`, kind: "plain" };
  }
  if (row.reason.includes("copied to trash")) {
    return { text: `${Actor} ${verb.past} ${files}${where} and Aegis kept a copy of each.`, kind: "plain" };
  }
  if (!files) return { text: `${Actor} ${verb.past}.`, kind: "plain" };
  return { text: `${Actor} ${verb.past} ${files}${where}.`, kind: "plain" };
}

/** The Status screen's single sentence. Describes only what the counters say. */
export function statusSentence(c: { waiting: number; blocked_today: number; actions_today: number }): string {
  if (c.waiting === 1) return "Aegis is watching your files. One request is waiting for you; nothing else needs doing.";
  if (c.waiting > 1) return `Aegis is watching your files. ${c.waiting} requests are waiting for you.`;
  if (c.blocked_today > 0)
    return `Aegis is watching your files. Nothing is waiting for you; it stopped ${
      c.blocked_today === 1 ? "one thing" : `${c.blocked_today} things`
    } today.`;
  if (c.actions_today === 0) return "Aegis is watching your files. Nothing has happened today.";
  return "Aegis is watching your files. Nothing is waiting for you and nothing has been blocked.";
}

/** The Approvals card headline. */
export function approvalHeadline(p: PendingApproval): string {
  const verb = toolVerb(p.tool).present;
  const folder = commonFolder(p.paths);
  const count = p.paths.length;
  if (count === 0) return `${Actor} wants to ${verb}`;
  const noun = count === 1 ? fileName(p.paths[0]) : `${count} files`;
  return folder ? `${Actor} wants to ${verb} ${noun} in ${folder}` : `${Actor} wants to ${verb} ${noun}`;
}

/** Button labels name the action, never "OK"/"Cancel". */
export function approvalButtons(p: PendingApproval): { allow: string; deny: string } {
  const verb = toolVerb(p.tool).present;
  return { allow: `Let it ${verb === "read" ? "read them" : verb}`, deny: "Don't let it" };
}

/** Why the approval is being asked — taken from the row's own rule_id. */
export function approvalWhy(p: PendingApproval): string {
  if (p.rule_id === "bulk_operation" || p.reason.includes("bulk threshold"))
    return `This touches more files at once than your rules allow without checking. Aegis is not judging what the files contain — only that there are ${p.paths.length} of them.`;
  return "Your rules mark this tool as one to check with you before it runs.";
}

/** A clock time for today, a date for anything older.
 *
 *  This used to return a bare "6:08 pm" for every row. Activity fetches the
 *  most recent rows by id with NO date filter, so a row from three days ago
 *  rendered as a time and read as today — while Status, which counts only rows
 *  since local midnight, correctly said nothing had happened today. The two
 *  screens appeared to disagree about the same database. Status was right; this
 *  was the screen dropping the day.
 */
export function formatTime(unix: number): string {
  const d = new Date(unix * 1000);
  let h = d.getHours();
  const m = d.getMinutes().toString().padStart(2, "0");
  const ampm = h >= 12 ? "pm" : "am";
  h = h % 12 || 12;
  const clock = `${h}:${m} ${ampm}`;
  if (d.toDateString() === new Date().toDateString()) return clock;

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return `Yesterday ${clock}`;

  return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short" })} ${clock}`;
}

export function formatSince(unix: number | null): string {
  if (unix === null) return "Not running";
  const d = new Date(unix * 1000);
  if (d.toDateString() !== new Date().toDateString()) {
    return `Last ran ${d.toLocaleDateString()}`;
  }
  const h = d.getHours();
  const m = d.getMinutes().toString().padStart(2, "0");
  const hour12 = h % 12 || 12;
  // "this morning" is only true before noon; after that say the time plainly.
  const when = h < 12 ? "this morning" : h < 18 ? "this afternoon" : "this evening";
  return `Running since ${hour12}:${m} ${when}`;
}

export function relativeTime(unix: number | null): string {
  if (unix === null) return "Never";
  const secs = Date.now() / 1000 - unix;
  if (secs < 90) return "A moment ago";
  if (secs < 3600) return `${Math.round(secs / 60)} minutes ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)} hours ago`;
  return `${Math.round(secs / 86400)} days ago`;
}

/* The FlowRow builder that used to live here has been removed with the Data
   flow table it fed (S6 fix 3). It mapped an allowed egress row to what/where/
   why/how-much, and three of those four were always "Not recorded" because the
   audit schema does not carry them. Keeping a tested, unused row-builder around
   would invite someone to wire it back up before the data exists. It comes back
   with the S8 schema change, not before. */

/** The chain verifier's message, trimmed to the part a person should read.
 *
 *  verify.py's first line is always the human summary ("audit chain broken at
 *  row id 3"); the lines after it are stored/recomputed hashes and a raw row
 *  dump that includes rule_ids. Passing the whole thing through put 64-char
 *  hex and rule_id='deny_paths' on screen — the same jargon this layer exists
 *  to remove. The verifier's own words are kept; only its debugging tail is
 *  dropped, and the full text is always available by running it directly.
 */
export function chainDetailSummary(detail: string): string {
  // Cut at the first newline OR the first run of two spaces: verify.py indents
  // its continuation lines, and something upstream flattening newlines to
  // spaces must not turn this back into a hash dump.
  const first = detail.split(/\n|\s{2,}/)[0].trim()
    .replace(/^FAIL:\s*/, "")
    .replace(/^OK:\s*/, "");
  return first.charAt(0).toUpperCase() + first.slice(1);
}
