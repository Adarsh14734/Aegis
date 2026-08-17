/** Shapes returned by the Rust side. These mirror the audit schema exactly —
 *  see aegis/audit.py. Nothing here is derived or invented; every field is a
 *  column or a direct count. */

export interface AuditRow {
  id: number;
  ts: number; // unix seconds, as stored
  tool: string;
  effect: string; // allow | deny | ask | redact
  rule_id: string;
  reason: string;
  paths: string[]; // parsed from the paths TEXT column (a JSON array)
}

export interface Counters {
  actions_today: number;
  waiting: number;
  blocked_today: number;
}

export interface PolicyView {
  /** Tool names the policy names — the closest thing the policy has to a list
   *  of agents. Empty if the policy cannot be read. */
  tools: string[];
  workspace_roots: string[];
  deny_paths: string[];
  allowed_domains: string[];
  credentials: string[];
  policy_path: string;
  loaded: boolean;
  error: string | null;
}

/** Result of shelling out to aegis/verify.py. The UI never recomputes the
 *  chain itself: verify.py is the authority, and a second implementation of
 *  the hash rule is a second thing to get wrong. */
export interface ChainStatus {
  ok: boolean;
  checked: boolean; // false if the verifier could not be run at all
  detail: string;
  db_path: string;
}

export interface PendingApproval {
  /** The audit row id of the approval_prompt row that is still unresolved. */
  prompt_id: number;
  ts: number;
  tool: string;
  rule_id: string;
  reason: string;
  paths: string[];
}

export interface Snapshot {
  chain: ChainStatus;
  counters: Counters;
  policy: PolicyView;
  recent: AuditRow[];
  pending: PendingApproval | null;
  running_since: number | null;
  /** True only in the browser dev harness. The UI paints a loud banner when
   *  set, so sample pixels can never be mistaken for a real audit log. */
  sample_data?: boolean;
}
