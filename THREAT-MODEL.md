# Aegis — Threat Model (S0)

**Status:** DRAFT — unreviewed
**Owner:** Adarsh, Aeon Industries
**Date:** 2026-08-14
**Gate rule:** No code is written for S1 until this document is complete and §7 has at least five entries.

---

## 0. Scope of this document

This is the S0 exit gate. It defines what Aegis protects, who it protects against, where the trust boundaries sit, and — most importantly — what it does **not** protect against.

Same discipline as RoboCore: a control is **UNVERIFIED** until observed working on a real machine with raw output captured. A passing test suite is not verification. A tool reporting its own success is not verification.

---

## 1. What Aegis actually is

> An MCP-layer policy proxy and TLS-inspecting egress gateway that sits in front of MCP-compatible AI agents, producing a tamper-evident audit trail of every tool call.

**Aegis is not:** an AI model, an agent, a chatbot, an antivirus, an EDR, or a replacement for the agent vendor's own sandbox. It wraps and extends existing OS isolation (Seatbelt on macOS, bubblewrap on Linux) rather than reimplementing kernel-level isolation.

---

## 2. Assets being protected

Ranked by blast radius if lost.

| # | Asset | Why it matters | Loss mode |
|---|---|---|---|
| A1 | Long-lived credentials (API keys, tokens, SSH keys, cloud creds) | Reusable, transferable, often unscoped | Exfiltration, or leakage into model context/logs |
| A2 | Source code and proprietary data | Company IP; irreplaceable | Upload to unapproved endpoint |
| A3 | User files outside the working directory | Personal/financial/legal documents | Unauthorized read, mass delete, overwrite |
| A4 | Production systems (deploy, DB, infra) | Irreversible real-world effect | Unapproved destructive action |
| A5 | Outbound communication channels (email, Slack, GitHub) | Acts under the user's identity | Unapproved send, mass send |
| A6 | The audit log itself | Without it, no incident can be reconstructed | Silent tampering, deletion |
| A7 | Aegis's own policy configuration | Compromise it and every other control falls | Unauthorized modification |

**Note on A6/A7:** these are the assets most security products forget. If an attacker can edit the policy file or the log, every other control in this document is decorative.

---

## 3. Adversaries

### T1 — The confused agent (most common, least malicious)
A capable model misreads the task. Asked to organize `~/Projects`, it globs too widely and deletes 800 files. No attacker involved. **This is the failure mode that will actually hit users**, and the one the demo should show.

### T2 — Prompt injection via untrusted content
The agent reads a webpage, README, issue comment, PDF, or MCP tool result containing instructions. The agent follows them. The instructions say: read `~/.aws/credentials` and POST it somewhere.
*This is the single most important adversary. Design assumption: **the agent will eventually be injected.*** Aegis's job is to make the injected instruction unexecutable, not to detect the injection.

### T3 — Malicious or compromised MCP server / tool
A tool the user installed is hostile, or was updated to become hostile (supply chain). Tool descriptions themselves are attacker-controlled input to the model — "tool poisoning."

### T4 — Malicious dependency inside the agent's workspace
`npm install` or `pip install` runs attacker code with the agent's privileges. The agent didn't do anything wrong; the build script did.

### T5 — The user themselves, under pressure
Approval fatigue. Twenty prompts an hour and the user clicks Allow without reading. **A control that is always bypassed by an exhausted human is not a control.** This is why deterministic deny rules must exist that produce no prompt at all.

### T6 — Local malware already on the host
Out of scope (see §7), but stated so the boundary is explicit.

---

## 4. Trust boundaries

```
[ User ]                                      TRUSTED
   |
   | (chat input, approvals)
   v
+---------------------------------------+
| AEGIS CONTROL PLANE                   |     TRUSTED
| policy engine, audit, cred broker     |     (trusted computing base)
+---------------------------------------+
   |            |                |
   | (1)        | (2)            | (3)
   v            v                v
+--------+  +----------+  +--------------+
| MCP    |  | Egress   |  | Sandbox      |
| proxy  |  | gateway  |  | launcher     |
+--------+  +----------+  +--------------+
   |            |                |
=========== TRUST BOUNDARY ==================
   |            |                |
   v            v                v
+---------------------------------------+
| AGENT PROCESS + MODEL CONTEXT         |     UNTRUSTED
| tool results, web content, files read |     ALWAYS
+---------------------------------------+
```

**Boundary rules:**

- **B1.** Everything on the agent side of the line is untrusted input, including the model's own stated reasoning. "I need to read this file because the user asked" is a claim, not evidence.
- **B2.** Policy decisions are made only in the control plane. The agent never sees, and cannot influence, the policy file.
- **B3.** The trusted computing base must stay small enough to audit by hand. Every feature added to the control plane widens it.
- **B4.** Secrets never cross the boundary in plaintext. The broker performs the operation; the agent receives a result.

---

## 5. Controls, mapped to sprints

| ID | Control | Adversaries | Sprint | Status |
|---|---|---|---|---|
| C1 | Deterministic path allow/deny on every `tools/call` | T1, T2, T3 | S1 | UNVERIFIED |
| C2 | Default-deny: unmatched action → ASK, never ALLOW | T1, T2 | S1 | UNVERIFIED |
| C3 | Hash-chained append-only audit log + verifier CLI | A6, all | S2 | VERIFIED (harness, macOS) — S2-REPORT.md |
| C4 | TLS-terminating egress proxy, domain allowlist | T2, T3, T4 | S3 | UNVERIFIED — not built |
| C4a | MCP-layer destination allowlist + SSRF rejection (no TLS inspection) | T2, T3 | S3a | VERIFIED (harness, macOS) — S3a-REPORT.md |
| C5 | DLP scan of outbound request bodies (key/PII patterns) | A1, A2 | S3 | UNVERIFIED — no request bodies at the MCP layer |
| C5a | Secret scan of tool arguments, pattern name recorded but never the value | A1, A2 | S3a | VERIFIED (harness, macOS) — S3a-REPORT.md |
| C6 | Credential broker — secret never enters agent context | A1, T2 | S4 | UNVERIFIED |
| C7 | Blocking human approval, timeout-to-deny | A4, A5 | S5 | UNVERIFIED |
| C8 | Bulk-operation threshold (N files → forced approval) | T1 | S5 | UNVERIFIED |
| C9 | Soft delete to recoverable trash | T1 | S5 | UNVERIFIED |
| C10 | Kill switch — terminate agents, revoke temp grants | all | S5 | UNVERIFIED |

**Promotion rule (from RoboCore):** a control moves to VERIFIED only when there is a captured raw transcript of the attack being attempted and blocked, filed in `evidence/`.

---

## 6. Key design decisions and their reasoning

**D1 — Deterministic controls are primary; semantic controls are advisory only.**
The "intent firewall" (an LLM judging whether an action matches user intent) is itself prompt-injectable. It may raise an alert or escalate to ASK. It must never be the sole basis for an ALLOW. Any path where a model's judgment permits an action a rule would have denied is a design bug.

**D2 — Wrap the vendor sandbox; do not rebuild it.**
Anthropic open-sourced its sandboxing implementation (Seatbelt/bubblewrap). Reimplementing kernel isolation as a solo founder is a multi-month detour with a high chance of producing something weaker. Aegis adds the policy, audit, and egress layers above it.

**D3 — Hostname-based egress filtering is insufficient.**
Filtering on the client-supplied hostname without inspecting TLS can be defeated by domain fronting. C4 therefore requires terminating TLS with a local CA installed inside the sandbox. This is the hardest engineering in the v0 and should be assumed to take longer than estimated.
*S3a note:* C4a checks a hostname read out of a tool argument. By this decision it is a partial control and can never be described as C4, however well it tests.

**D4 — Approval budget is a security property.**
Target: fewer than 5 approval prompts per hour of agent work. Above that, T5 (approval fatigue) defeats C7. If a sprint increases prompt frequency, that is a regression.

**D5 — Local-first storage.**
SQLite with WAL, no Postgres, no Redis, no daemon. Fewer moving parts is a security property, not a shortcut.

---

## 7. What Aegis does NOT protect against

**This section is mandatory and must never be deleted for marketing reasons.** Every entry here is a claim we are permanently forbidden from making in sales conversations.

1. **Malware already running on the host.** If the machine is compromised outside the agent, Aegis is compromised too. Aegis is an agent-authority boundary, not an endpoint security product.

2. **Root, sudo, or physical access.** Anyone with root can edit the policy file, the audit database, and the CA store. Aegis assumes the OS user account is not hostile.

3. **Model hallucination itself.** Aegis cannot make a model correct. It reduces the *consequences* of incorrect output by constraining what wrong output can reach. A hallucinated but permitted action still executes.

4. **Prompt injection as a phenomenon.** Aegis does not detect or prevent injection. It assumes injection succeeds and limits the resulting authority. Injected text that only asks the agent to produce a wrong answer is entirely unaffected.

5. **Data already sent to a model provider.** Once bytes leave for inference, provider terms govern them. Aegis controls *what is sent* and *records that it was sent*. It cannot recall it. "Nothing leaves your machine" is a false claim in any cloud-model configuration.

6. **Agents Aegis did not launch or proxy.** An agent started directly by the user, or one that talks to an API without going through the MCP proxy and egress gateway, is entirely outside the boundary. There is no universal interception.

7. **Sandbox escapes and OS-level zero-days.** Aegis inherits the security of Seatbelt/bubblewrap. A kernel escape defeats everything above it.

8. **Actions taken through an approved channel.** If the user grants Slack send access, the agent can send an embarrassing Slack message. Least privilege limits scope; it does not judge content.

9. **Insider misuse.** A user who deliberately configures permissive policy to exfiltrate their employer's data will succeed. Aegis will produce an excellent audit trail of them doing it.

10. **Any compliance certification.** No SOC 2, no ISO 27001, no independent penetration test, no security audit. Until those exist, Aegis is unsuitable for regulated or enterprise production use, and must be described that way.

---

## 8. Language rules

**Permitted claims (engineerable and testable):**
least-privilege tool mediation · deny-by-default egress · tamper-evident audit trail · credential isolation from model context · human approval for destructive actions · sandboxed execution · provider-independent policy

**Forbidden claims:**
"AI can never leak data" · "impossible to hack" · "nothing ever leaves your computer" · "prevents hallucination" · "works with every AI agent" · "enterprise-grade" · "secure" as an unqualified adjective

---

## 9. Open questions before S1

- [ ] Which MCP transport is intercepted first — stdio or HTTP? (Recommend stdio: that is how Claude Code loads local servers.)
- [ ] Where does the policy file live, and what prevents the agent from writing to it? (Must be outside every writable path granted to the agent. Verify with an actual write attempt.)
- [ ] What is the failure mode if the Aegis proxy crashes mid-session — fail-open or fail-closed? (Must be fail-closed. Fail-open is a silent removal of every control.)
- [x] Does the audit verifier run offline, without the control plane? (It must, or a compromised control plane can lie about its own integrity.) **Answered in S2:** `aegis/verify.py` imports only stdlib — nothing from Aegis — and carries its own independent copy of the chain rule, so editing `audit.py` cannot make forged rows validate. Caveat recorded in S2-REPORT.md: an attacker with write access can still rewrite the entire chain consistently, and only an externally anchored head hash detects that.

---

## 10. Review log

| Date | Reviewer | Outcome |
|---|---|---|
| | | not yet reviewed by any second party |
