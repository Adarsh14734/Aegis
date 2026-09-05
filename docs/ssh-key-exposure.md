

# Four routes to your SSH key from an AI coding agent

## 1. The setup

Default macOS on Apple Silicon. Claude Code, installed normally. One project directory with a `.env` in it. Nothing unusual, nothing hardened, no special configuration.

The question: what can the agent reach outside that directory?

## 2. What it reaches

An AI coding agent runs as you. It has your permissions, and its shell tool has them too. `~/.ssh/id_rsa` and `~/.aws/credentials` are ordinary readable files to a process running under your account — nothing in the OS distinguishes "the agent asked for this" from "you asked for this."

Four routes reach the same file:

1. The agent's own `Read` tool
2. `cat` through its shell
3. `find` across the filesystem
4. An MCP filesystem server with a root above the file

Different mechanisms, one outcome. The client's built-in permission rules cover some of them, some of the time, in some clients. They're configuration, not a boundary.

## 3. Why asking the model nicely isn't a control

On 27 August, Reuters reported that Russian-speaking operators used Cursor's AI agent against seven companies. What they did to get past its safety behaviour is the important part: they told it the intrusion was an authorized security test. When the agent refused some requests, the operators restarted the conversation and repeated the claim, and in one log the agent reasoned that a test environment made the activity legal.

The guardrail wasn't broken. It was **argued with**, and it lost.

That's the general shape of model-level protection: it depends on the model's judgment about context, and context is supplied by whoever is talking to it. A refusal you can talk someone out of is a preference, not a boundary.

The alternative isn't a smarter model. It's a rule that doesn't have an opinion.

## 4. What isn't negotiable

Same machine, same agent, Aegis in front. The agent's shell, invoked directly with `!` so the model isn't in the loop:

```
$ ! cat ~/.ssh/id_rsa
cat: /Users/adarsh/.ssh/id_rsa: Operation not permitted

$ ! cat ~/.aws/credentials
cat: /Users/adarsh/.aws/credentials: Operation not permitted
```

And the record:

```
kernel denied file-read-data /Users/adarsh/.ssh/id_rsa to cat(pid 41560)
kernel denied file-read-data /Users/adarsh/.aws/credentials to cat(pid 42180)
```

`to cat` — the refusal names the process that tried. Not the model declining. Not the client's permission rules. The kernel.

**The part worth dwelling on:** across three separate sessions, the agent diagnosed this as macOS TCC and suggested granting Full Disk Access in System Settings. It was wrong every time. It never identified what actually stopped it, proposed a workaround that wouldn't have helped, and the file stayed unread.

A model can be argued out of a refusal. It cannot be argued out of a rule it can't see and doesn't understand.

## 5. The proxy layer

The same test at the MCP layer, with no client and no model anywhere — raw JSON-RPC, same tool, same file:

```
direct to the server:   allowed: TOKEN=proof-env-secret
through aegis proxy:    AEGIS DENIED: read_text_file
                        Reason: path matches deny rule '.env'
                        Rule: deny_paths
```

The file is *inside* the server's own allowed root. The server reads it happily. Only the proxy refuses. And `notes/todo.md` passes through fine, so it isn't blocking indiscriminately.

## 6. Reproduce it

```bash
pip install aegis-mcp
mkdir ~/aegis-test && cd ~/aegis-test
echo "SECRET_KEY=test" > .env
aegis init      # accept the wrapper, the endpoints, the state paths, the PATH line
aegis doctor    # every check should pass
claude
```

Then in the session: `! cat ~/.ssh/id_rsa`

## 7. What this doesn't cover

Aegis is exactly as strong as Seatbelt underneath it. A kernel escape returns the agent to full authority, and Aegis would neither prevent nor notice it.

The wrapper is a PATH entry, and PATH is advice. Invoking the real binary path directly bypasses it. So does a process that was already running — constraining one on macOS needs an Endpoint Security entitlement Apple grants to registered organizations, which no `pip install` can supply.

Reading `~/.claude` is not restricted and can't be: the client must read its own settings and credentials to start. If your install keeps its OAuth token in a file rather than the Keychain, that file is readable by anything in the sandboxed tree.

`/tmp` is granted so clients can start at all. Deny paths still apply there, but a sandboxed process can write arbitrary files to a world-writable directory.

Denial attribution matches the sandbox tag, which encodes the command truncated to 100 characters. Two concurrent runs of the same command still attribute each other's denials. The honest claim for a log row is "an `aegis run` of this command denied this path" — not "this session did."

And attribution is not integrity. `audit.db` remains writable from inside the sandbox.

No external security review. No certifications. Not audited by anyone but me.

## 8. What this is

Aegis is a free, local, MIT-licensed policy proxy and kernel sandbox for AI coding agents. macOS Apple Silicon only. No account, no cloud, no telemetry.

`pip install aegis-mcp` · github.com/Adarsh14734/Aegis

---

