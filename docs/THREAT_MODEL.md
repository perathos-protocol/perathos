# Perathos Threat Model

_Last updated: 2026-11-10. Covers `perathos` on `main` after 1.4.1 and the
Perathos Gate server (`perathos-protocol/perathos-gate`) as read on that date._

This document says what Perathos protects, what it does not, and what a
deployment must do to get the stronger properties. It is written so that a
security reviewer can decide what to trust without reading the source. Every
"Yes" below was checked against the code or a specification in this
repository. Where something was not checked, it says so.

The short version: Perathos produces **evidence, not guarantees**. A valid
record shows that a key holder sealed a particular sequence of events and that
nobody changed it afterwards. It does not show that the record is complete,
that the agent was well behaved, or that an approver understood what they
approved.

Contents:

1. [Scope and non-goals](#1-scope-and-non-goals)
2. [Assets](#2-assets)
3. [Trust boundaries](#3-trust-boundaries)
4. [Adversaries](#4-adversaries)
5. [Threats by component](#5-threats-by-component)
6. [What each adversary can still do](#6-what-each-adversary-can-still-do)
7. [Residual risks and roadmap](#7-residual-risks-and-roadmap)
8. [Deployment requirements for the stronger properties](#8-deployment-requirements-for-the-stronger-properties)
9. [Cryptographic choices](#9-cryptographic-choices)

## 1. Scope and non-goals

In scope:

| Component | Code | Specification |
|---|---|---|
| Flight recorder: hash-chained receipts, signed checkpoints | `perathos/recorder.py` | [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md) |
| RFC 3161 anchors | `perathos/anchor.py` | [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md), "Anchors" |
| Destructive-command guard and signed preconditions | `perathos/guard.py` | [specs/PRECONDITION_V1.md](specs/PRECONDITION_V1.md) |
| Hooks for Claude Code and Cursor, and the MCP proxy | `perathos/hook.py`, `perathos/hooks.py`, `perathos/integrations/cursor.py`, `perathos/mcp_proxy.py` | |
| Remote signers and approver keys | `perathos/signers.py`, `perathos/approvers.py` | |
| Evidence packs | `perathos/evidence.py` | [FOR_AUDITORS.md](FOR_AUDITORS.md) |
| Perathos Gate client and receipt verifier | `perathos/gate.py` | [specs/GATE_V1.md](specs/GATE_V1.md) |
| Perathos Gate server (separate repository, AGPL-3.0) and the hosted instance at `gate.perathos.com` | `perathos-protocol/perathos-gate` | [specs/GATE_V1.md](specs/GATE_V1.md) |
| Proof bundles (the original layer) | `perathos/bundle.py`, `perathos/signing.py`, `perathos/keytrust.py` | [specs/BUNDLE_V2.md](specs/BUNDLE_V2.md) |

Non-goals. Perathos does not try to do any of these, and nothing in it should
be read as doing them:

- **It is not a sandbox.** The guard matches patterns in commands. It does not
  confine a process, and it cannot stop a command it does not recognise.
- **It does not prove completeness.** It records the tool calls its hooks see.
  It cannot show that the hooks were on for the whole of the work.
- **It does not prove which model ran.** The `model` field is self-reported.
- **It does not provide confidentiality.** Logs, preconditions, bundles and
  packs are tamper-evident, not encrypted.
- **It does not judge the agent's intent or the truth of its output.**
  Verifier verdicts in proof bundles are evidence with false negatives.
- **It does not replace least privilege.** Run agents with the narrowest
  credentials and file access you can, whatever Perathos is doing.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Session logs (`<project>/.perathos/sessions/*.jsonl`) and head witness files | The record of what the agent did |
| Recorder signing key (default `~/.perathos/keys/signing.key`, or a remote signer) | Whoever can use it can seal a log that verifies as the operator's |
| Approver keys, and the list of trusted ones (`~/.perathos/approvers.json`) | Whoever can sign as an approver, or edit the list, can authorise destructive commands |
| Anchors (`~/.perathos/anchors/*.jsonl`) and any off-machine copy | Independent time, and the means to detect a cut-off log |
| Hook configuration (`.claude/settings.json`, `.cursor/hooks.json`, the managed settings file, MCP client configuration) | If hooks are removed, nothing is recorded or blocked |
| Perathos configuration (`~/.perathos/config.json`) | Names the signer, the anchor mirror, the Gate URL, the Gate API key and the pinned Gate key |
| Gate server signing key | Whoever holds it can issue receipts that verify against the pinned Gate key |
| Approvers' passkeys | Whoever can use one can approve through the Gate |
| Gate organisation API key | Lets the holder create approval requests and read their status |
| The mapping from a public key to a real person or organisation | Provenance. It exists only outside Perathos |

## 3. Trust boundaries

**The agent process.** Not trusted. It may be careless or hostile. Perathos
sees its tool calls only through hooks that the agent tool (Claude Code,
Cursor, an MCP client) chooses to run.

**The machine.** By default the hooks, the logs, the signing key, the approver
list, the configuration and the agent all sit under one operating-system user.
There is no boundary between them except what the guard's patterns deny. An
agent with unrestricted shell access as that user is inside the boundary.

**The signing key location.** With the default `local` signer the key is a
cleartext hex file under `~/.perathos/keys/`, with owner-only permissions
(POSIX `0o600`; on Windows an owner-only ACL via `icacls`, best effort with a
warning on failure). With a remote signer (`vault:`, `gcpkms:`, `command:`)
the private key stays in the remote service. The hook still has to be able to
ask for a signature without a person present, so the credential that
authorises signing is usually reachable from the same user account. See
section 5.5.

**The Gate server.** A separate service. It stores requests, shows them to
approvers, checks passkey assertions and signs receipts with its own Ed25519
key. The client trusts it for exactly one thing: receipts signed by the pinned
Gate key. That is a large trust, set out in section 5.7.

**The approver's device.** Holds the passkey. Perathos trusts the device's
browser and authenticator to show the right origin and to require user
verification. It learns nothing about the device itself: the server asks for
no attestation.

**The Time Stamping Authority (TSA).** Trusted for time only. A token is
accepted only if it chains to a root pinned in the package (default: the
freetsa.org root) or supplied by the verifier. The TSA sees a hash, a nonce
and the caller's IP address.

**The verifier.** Whoever checks a log, pack or receipt. They must obtain the
signer's public key, and the Gate key, through a channel other than the thing
being verified. Without that, verification shows internal consistency only.

## 4. Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | A careless agent | Runs a destructive command by mistake, in the plain form a person would type. Does not try to evade anything. |
| A2 | A hostile agent with shell access on the same machine | Runs arbitrary commands as the operator's user. Will obfuscate commands, read files, edit configuration and call network services. |
| A3 | A tamperer with the log after the fact | Has write access to the log files later (the operator, a colleague, an intruder). May or may not have the signing key. |
| A4 | A network attacker | Can read, block or alter traffic between the machine and the TSA, the Gate, or a remote signer. Cannot break TLS without a mis-issued certificate. |
| A5 | A malicious or compromised Gate server | Controls the Gate's code, database and signing key. |
| A6 | A phished or pressured approver | An honest approver who is deceived, hurried or tired, or whose passkey account or unlocked device is taken over. |

## 5. Threats by component

"Protected?" is **Yes**, **Partly** or **No**. "Partly" always says what the
part is.

### 5.1 Flight recorder

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| Editing, deleting, inserting or reordering a receipt before the last signed checkpoint (A3 without the key) | Yes | Each receipt carries the previous receipt's hash and its own hash over every field. `seq` must run 1, 2, 3. A signed checkpoint commits to everything before it. `session verify` reports the break. |
| Stripping or forging a checkpoint signature | Yes | Unsigned checkpoints fail verification by default (`ERR_UNSIGNED`). The signature is Ed25519 over the receipt hash, and the signer's key is bound into the hashed body. |
| Re-signing a rewritten log with a different key | Partly | Detected only when the verifier pins the expected key (`--verify-key`) or a trust set (`--trust-jwks`). Without a pin the result is `VALID_UNCONFIRMED_SIGNER`, not `VALID`. |
| Rewriting a log and sealing it with the real key (A2 or A3 with the key) | No | Anyone who can use the signing key can produce a different, fully valid log. With the default local key, an agent that can read the key file can do this. Off-machine anchor copies limit it: a rewritten checkpoint no longer matches the anchor already held elsewhere. |
| Changing receipts after the last checkpoint (the unsealed tail) | No | Tail receipts are chained but not yet signed. They can be rewritten consistently or removed. The verifier reports the tail as unsealed, as a warning. |
| Cutting off the end of a log, back to an earlier checkpoint | Partly | Detected if the head witness file survives, or if an anchor for a later checkpoint is presented. The head witness sits beside the log and can be deleted with it. Reliable detection needs an anchor copy the attacker cannot reach. |
| Deleting a whole session log | No | Nothing in Perathos lists the sessions that should exist. An off-machine anchor copy shows that a session with that id once had checkpoints. |
| A period with hooks switched off | No | A session with no hooks produces no receipts. Hooks removed between sessions leave no trace in any log. See 5.4. |
| A hook that fails while recording | Partly | The tool call proceeds, so that the recorder never breaks a session, and the receipt is missing from the log: the log itself does not show the gap. The error is printed to stderr and one line is appended to `~/.perathos/errors.log`; `perathos doctor --recorder` and `perathos session verify` report the count on that machine. That file is local, unsigned, writable by the agent's user and not part of an evidence pack, so it helps an operator notice a fault and proves nothing to a third party. A failure that also stops the error log being written is visible on stderr only. |
| Backdated or wrong event times | Partly | `ts` is the local clock. The verifier rejects timestamps that go backwards and nothing else. An anchored checkpoint has an independent upper bound on its time (5.2). |
| Learning tool arguments or output from the log | Partly | Only SHA-256 hashes are stored. A short or guessable value can be confirmed by hashing guesses. |
| Proving which model produced the calls | No | `model` is read from the agent tool's transcript (Claude Code) or hook payload (Cursor). It is self-reported and the MCP proxy records none. |
| Malformed or hostile log crashing the verifier | Yes | `verify_session` returns an error report for unreadable, malformed or non-object lines. Not fuzzed beyond the test suite. |

If the configured signer cannot be loaded, or fails while signing, when a
checkpoint is due, the recorder still writes the checkpoint, **unsigned**, with
`signer_error` (the error's class name) inside its hashed body. It prints a
warning on stderr and adds a line to `~/.perathos/errors.log`. A default
verification then fails with `ERR_UNSIGNED` and names the signer failure as
the cause, even if later checkpoints are signed; `session verify` shows the
count. The gap is visible, but the turn is not sealed, and `signer_error` is
only the recorder's own explanation. (Before this change a signer that failed
during signing, as opposed to loading, lost the checkpoint altogether, and the
Cursor hook gave no warning.)

### 5.2 Anchors (RFC 3161 timestamps)

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| A forged timestamp token | Yes | A token is accepted only if it verifies over the checkpoint hash and chains to a pinned root. Certificates carried inside the token are never used as trust anchors. |
| A token for a different checkpoint | Yes | The message imprint is SHA-256 over the raw checkpoint hash. A mismatch is `ERR_ANCHOR_MISMATCH`. |
| Claiming a checkpoint existed earlier than it did | Yes, to the TSA's honesty | The TSA asserts "this hash existed at time T". The verifier also warns when a checkpoint's local time is more than five minutes after its TSA time. |
| Claiming events happened later than they did | No | An anchor is an upper bound. It does not show when the events before the checkpoint took place, only that they were sealed by time T. |
| Truncation after an anchored checkpoint | Partly | An anchor for a checkpoint missing from the log yields `ERR_TRUNCATED`. This works only if the verifier is given an anchors file the attacker could not edit. The default file is on the same machine, under `~/.perathos/anchors/`. |
| A network attacker blocking the TSA (A4) | No | Anchoring fails quietly: the checkpoint stays signed but unanchored, and the hook reports the error on stderr. `session verify --require-anchor` makes the gap a failure. |
| A dishonest or compromised TSA | No | The TSA is trusted for time. Whoever holds its key can assert any time. The default TSA is a third party this project does not control. |

The browser verifier checks that each anchor matches its checkpoint. It does
not check TSA token signatures; the CLI does.

### 5.3 Guard and signed preconditions

The guard is a **pattern matcher**. It compares the command text, some script
files the command runs, and MCP tool names and arguments against a list of
regular expressions. The list changes between releases and is not described
here; see the [README](../README.md#destructive-command-guard) and
`perathos/guard.py`.

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| A destructive command typed in a plain, recognisable form (A1) | Partly | Denied if it matches a rule and no valid precondition or Gate approval covers it. A destructive command that no rule describes is not seen. Coverage is tested against a corpus (`tests/test_guard_hardening.py`), not proven. |
| Discarding uncommitted work with git | Partly | Whole-tree discards are denied: `checkout -f`, `checkout [<tree>] [--] .` (also `./`, `:/`, `*`), `restore .` unless it only unstages (`--staged` without `--worktree`), `switch -f` / `--discard-changes`, `reset --hard`, `clean -f`. Discarding changes to named files or directories is allowed and consistent across both commands: `git checkout -- a.py`, `git checkout feature -- ci.yml`, `git restore a.py`, `git restore src/`. |
| SQL words in text that never reaches a database | Allowed only for a line of text-only commands | The SQL, Redis and MongoDB rules skip a command line only when every command on it, and in its substitutions, is a text-only program (`echo`, `printf`, `grep`, `jq`, `yq`, `Write-Host`, `Write-Output` and `Select-String` without `-OutVariable` / `-PipelineVariable`, `rg` without `--pre`; `git` only for an allow-list of built-in subcommands such as commit, tag, log, show, diff, push, with `config` only reading, and never with `-c`, `--config-env`, `--exec-path`, `-o` / `--output`, `--ext-diff`, `--textconv`, `-S` / `--gpg-sign` or a `GIT_*`, `*PAGER` or `*EDITOR` assignment, since aliases, settings, pagers and editors run programs; `gh` and `glab` only for `pr`, `issue`, `release` or `repo` with view, list, create, comment, edit or status and no `--template`; not `sed`, `awk`, `ack`, `ag`, `hg`, `svn` or `jj`) or a neutral one (`cd`, `pwd`, `true`, `false`, `:`); there is no pipe and no output redirect except `>/dev/null`, `2>/dev/null`, `2>&1`, `>&2`, `1>&2`, `2>file`, `$null` and `NUL`; there is no brace group, `exec`, `coproc` or `printf -v`; no database client is named anywhere (after removing backslash and `^` escapes, folding Unicode compatibility forms and cutting `${...}` / `$name` out of words); no program is computed (PowerShell `&` or `.` before anything but a plain word, `iex`, `eval`, `source`, `xargs`, a variable as the program, `sh -c`, `cmd /c`, `powershell -c`); none of `$(`, a backtick, `<(`, `>(`, `=(`, `${`, `$'` or a backslash-escaped quote or bracket appears; and all brackets match. So `git commit -m "fix: drop table handling" && git push` is allowed. Otherwise the rules read all the text, as main does: a commit message written through `$(cat <<'EOF' ...)` or `git commit -F - <<EOF` that names SQL, SQL written to a file with `echo`, `printf` or a heredoc, and a line that names both a client and SQL are denied. In scripts, file writes and MCP arguments the rules always read all the text. |
| `--help` on a destructive command | Denied | `terraform destroy --help` is blocked like the command itself. An exemption was tried and dropped: `--help` can be an option's value or an argument after `--` (`kubectl delete ns prod -- --help`, `helm uninstall x --description --help`), and the command still runs. A false positive here is the accepted cost. |
| Very long input | Yes, fails closed above a cap | The whole text is matched; no rule's reach is capped. A shell command over 65,536 characters, or a script write's content or an MCP call's string arguments over 700,000 characters in total, is denied without being matched (`guard.too-long`, "too long to check safely; split it or write it in parts"); no precondition covers it. To keep the time bounded, "keyword, gap, target" rules try only the first keyword in each stretch the gap can span, rules with two gaps (`git push ... -f ... main`, `docker compose ... down ... -v`) take the leftmost match of each target, and download-then-run, rmtree-by-name and git restore are one-pass matchers; these give main's answers (checked by a differential test against main) except a gcloud group name split across a line end. Double-quoted strings are delimited from one pass over the quotes (a long run of unclosed `"` / `\"` used to take minutes at the command cap). Measured worst case on the development machine over about 140 adversarial shapes, taking the slowest of several runs: up to 1.2 s at the command cap and up to 2.8 s at the content cap (the same shapes ran up to 2.5 times faster in other runs; at 800,000 characters the worst reached 3.4 s, which is why the content cap is 700,000), against the hook's 10 s timeout. These are measurements, not a proof: an input shape not tried could be slower, and a slower machine is. |
| SQL the command text does not spell out | No | The SQL, Redis and MongoDB rules read the command text only. They do not see a query that is encoded or transformed (`base64 -d`, `tr`, `rev`), one that comes from a file, git, or the network (`cat existing.sql \| psql`, `git show HEAD:drop.sql \| psql`, `curl ... \| psql`), one built in a program (`'DR' + 'OP TABLE'` in Python), one whose keyword is split by a substitution (`psql -c "DR$(echo)OP TABLE t"`, `redis-cli FLUSH$(echo ALL)`), one split across lines inside a quoted argument, a Redis `EVAL` script, or MongoDB bracket access (`db['dropDatabase']()`). The same holds on main. |
| A deliberately disguised command (A2) | No | Environment-variable indirection, downloaded scripts, encodings, a compiled helper, or a tool the guard does not inspect all get past a pattern. This is inherent. |
| The agent creating its own precondition or new key through the CLI | Partly | Commands that match `perathos precondition` or `perathos keygen` are denied. The denial is a pattern, with the limits above. The real control is that the agent cannot use an approver key. |
| The agent reading the signing key, or changing hook files or `.perathos/` | Partly | Commands and file-tool calls that name those paths are denied (read-only commands on the hook files are allowed). Path spellings are folded first (backslashes, `./`, `//` and `dir/..` segments), so `.claude/./settings.json` counts as `.claude/settings.json`; globs, a `cd` into the directory and renaming the directory are not caught. An agent with shell access can reach a file by a route the patterns do not name. Operating-system permissions are the real control. |
| A forged or altered precondition | Yes | The precondition hash covers every field. The signature must verify under a key in the trusted set, and the key must equal `signer`. |
| A precondition signed by an untrusted key | Yes | Once any approver is listed, only listed keys are trusted. With none listed, the local recorder key is the only trusted key. With no key at all, every matched call is denied. |
| An agent that can use a trusted key | No | With the default local key the recorder key is also the approver key. An agent that reads it can sign its own precondition without the CLI. |
| An agent that edits the approver list | No | `~/.perathos/approvers.json` is a local, unsigned file. An agent that can write it can add its own key. Guard patterns deny the obvious routes only. |
| An expired precondition | Yes | Rejected at or after `expires`, judged by the local clock. |
| Reuse of a precondition | No | A v1 precondition is not consumed. It covers any number of matching commands until it expires, in any session or project that holds the file. |
| A precondition that covers more than intended | Partly | Scope must appear in the command as a whole token. Scope `*` covers everything. A scope that names a common word covers every command containing it. |
| A check that proves little | No | A precondition shows that a named command ran and exited 0. Whether that command tests the safeguard is the signer's judgement. A `manual_reason` precondition shows only the signer's word. |
| A check influenced by the agent | No | The check runs in the project directory. If the agent could alter the files or tools the check uses, the result can be arranged. Not addressed by Perathos. |
| The decision being altered after the fact | Yes | The `guard` field (decision, rule, precondition hash, Gate approval hash) is inside the `pre` receipt's hash, written before the call runs. Subject to 5.1. |
| The guard crashing | Yes | In the Claude Code and Cursor hooks and in the MCP proxy, an exception in the guard denies the call and records it as denied (`guard.error`). The MCP proxy answers the client with an error result and does not forward the call. (Through 1.4.1 the proxy logged the exception and forwarded the call.) This covers an exception inside the guard; a hook process that never starts is 5.4. |

### 5.4 Hooks and the MCP proxy

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| The guard hook process missing or crashing | Partly | The installer sets `onFailure: "block"` on the Claude Code guard hook and `failClosed: true` on Cursor's guarded hooks. Enforcement is by the agent tool. The code notes that Claude Code versions before 2.1.295 ignore the setting. |
| The agent removing or editing project or user hooks (A2) | Partly | The guard denies commands and file writes that name the hook files. A pattern, as above. |
| The agent removing managed hooks | Yes, to the agent tool's enforcement | `perathos hooks install --scope managed` writes Claude Code's managed policy file and sets `allowManagedHooksOnly`. The file needs administrator rights to change. Perathos relies on Claude Code honouring the setting and on the agent not having administrator rights. There is no equivalent for Cursor in this repository. |
| Work done outside the hooked tool | No | Another terminal, another agent, a different MCP client, or a tool the integration does not hook is not recorded. |
| Cursor tools other than shell, MCP and file edits | No | Cursor's other built-in tools are not recorded. File edits are reported after they happen, so the guard cannot stop one. |
| MCP calls that do not go through the proxy | No | The proxy sees only the traffic of the server it wraps, and only if the client is configured to start it. |
| MCP messages the proxy cannot parse | No | They are relayed untouched and not recorded. Only `tools/call` requests and their responses become receipts. A line is forwarded as the client sent it, so a server whose JSON parser reads a message differently from Python's (for example on duplicate keys) could see a call the proxy did not. Not tested. |
| A destructive `tools/call` inside a JSON-RPC batch, or sent as a notification (no `id`) | Yes, with `--guard` | Each call in a batch is guarded and recorded on its own; denied ones are answered by the proxy and the rest forwarded. With `--guard`, a `tools/call` notification is guarded too and dropped when denied. Without `--guard`, notifications are relayed and not recorded. |
| The Stop-hook summary check being read as a lie detector | No | `hooks stop-check` flags a specific claim with no support in the session's tool output. It does not catch a grounded but misleading summary, it never blocks, and its receipt is unsigned if no local key exists. |

### 5.5 Remote signers and approver keys

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| Copying the recorder key off the machine | Yes, with a remote signer | With `vault:`, `gcpkms:` or a suitable `command:` signer the private key is not on the machine. With `local` it is a readable file. |
| A hostile agent asking the remote signer to sign | No | The hook must sign without a person present, so its credential (for example `VAULT_TOKEN`, or application default credentials) is normally available to the same user as the agent. An agent that can use that credential can have a forged checkpoint signed. What a remote signer adds is that the key cannot be copied, and that use can be logged, limited and revoked on the signer's side. Perathos does not verify how the credential is protected. |
| A remote signer returning a bad signature | Yes | Every remote signature is verified against the signer's public key before it is used. |
| A network attacker substituting the remote signer's key (A4) | Partly | The public key and the signatures come over the same channel, so the self-check does not catch a consistent substitution. A verifier that pins the expected key does. |
| The recorder key approving destructive actions | Yes, once approvers are listed | With at least one listed approver the recorder key is no longer trusted for preconditions unless it is listed too. |
| An approver key held away from the agent | Yes, if it is | `perathos precondition add --signer ...` lets an approver sign with a key the agent's user cannot use. Perathos cannot check where an approver keeps their key. |
| Key rotation and revocation | Partly | A new key is a new pin. Removing an approver invalidates their preconditions at once. There is no revocation service, and old logs stay valid under the old key. |

### 5.6 Evidence packs

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| A file in the pack changed, added or removed after export | Yes | `MANIFEST.json` lists the SHA-256 of every file and is signed. Unlisted, missing and modified files are errors. An unsigned manifest is an error. |
| A pack rebuilt and signed by someone else | Partly | Detected only when the verifier pins the signer (`--verify-key`). Otherwise the result is `VALID_UNCONFIRMED_SIGNER`. |
| Trusting the exporter's own report | Yes | `evidence verify` re-runs session verification from the pack's copies. The exporter applies the same precondition and approval cross-check before writing its report. Both the export and `evidence verify` fail when a cited precondition is missing (`ERR_PRECONDITION_MISSING`), or when a cited approval is missing, is not an approve decision, or was given for other arguments (`ERR_APPROVAL_MISSING`, `ERR_APPROVAL_NOT_APPROVED`, `ERR_APPROVAL_ARGS_MISMATCH`), so the export does not report VERIFIED for such a pack. The export does not check Gate signatures; `evidence verify` does. `REPORT.html` and `verification.json` are the exporter's statements and should be read as such. |
| A hostile zip | Partly | Paths that escape the extraction directory are rejected. No limit on decompressed size was found in the code. |
| An altered precondition in the pack | Yes | Each precondition's hash and signature are re-checked. |
| A call recorded as allowed under a precondition the pack does not carry | Yes | Every `guard.precondition` hash cited by an allowed `pre` receipt must match a precondition file in the pack (`ERR_PRECONDITION_MISSING`). The browser verifier makes the same check. |
| A head witness that does not match the log in the pack | Yes | `evidence verify` applies the same head check as `session verify`: a head witness past the last checkpoint is `ERR_TRUNCATED`, and one whose hash differs from the checkpoint at its seq, or that has no usable `seq` and `receipt_hash`, is `ERR_HEAD_MISMATCH`. The browser verifier agrees, with one known difference: JavaScript's JSON parser cannot tell `5` from `5.0`, so a head witness whose `seq` is written as a float with a zero fraction passes in the browser but is `ERR_HEAD_MISMATCH` in the CLI. The recorder always writes an integer. |
| A precondition signed by someone who was not an approver | No | `evidence verify` checks that each precondition is signed by its own stated `signer`. It does not compare that signer with `approvers.json` or any pin. The reviewer must. `approvers.json` in the pack is the exporter's list, covered only by the manifest signature. |
| A forged Gate approval in the pack | Partly | Each receipt in `approvals/` is verified (Gate signature, passkey signature, challenge binding). It is checked against a Gate key and approver passkeys only if the verifier supplies them (`evidence verify --gate-key <hex> --approver-key <b64url>`) or has them pinned locally. A reviewer's machine normally has neither, so the output states which applied: `Gate key UNCONFIRMED` (and a first word of `VALID_UNCONFIRMED_GATE`) or `approvers NOT PINNED`. Without the Gate key, a receipt signed by any Gate passes as internally consistent. Without approver keys, whoever holds the Gate signing key could have named a passkey of their own (5.7). Both keys must come from outside the pack. |
| A call recorded as approved with no matching approval | Yes | Every `guard.approval` hash cited by a `pre` receipt must match a receipt in the pack (`ERR_APPROVAL_MISSING`) whose decision is approve (`ERR_APPROVAL_NOT_APPROVED`) and whose `args_hash` equals the citing receipt's (`ERR_APPROVAL_ARGS_MISMATCH`). One approval cited by several calls is a warning. Not checked: that the call's local-clock time fell inside the approval's validity window. Approvals of Cursor shell commands made by 1.4.1 or earlier were bound to a different form of the arguments hash and fail the last check. |
| A pack built from an incomplete or rewritten log | No | A pack is as complete and as honest as the log it was built from. See 5.1. |

The browser verifier does not check Gate receipts at all: not their
signatures, and not the cross-check against the log. Its page says so.

### 5.7 Perathos Gate

How it works, in one paragraph. The guard (or any program with the
organisation API key) posts a request holding the action text and `args_hash`.
The server shows it to an approver, who approves or denies with a passkey. The
WebAuthn challenge is a hash of the request and the decision. The server
checks the assertion against the enrolled credential, builds a receipt
containing the assertion and the approver's public key, and signs it. The
client verifies the receipt offline and allows the call only if the decision
is approve, the receipt is unexpired, and `args_hash` equals the hash of the
arguments about to run.

What the offline verifier checks (`perathos/gate.py`, `verify_receipt`): the
receipt hash; the server signature, and that its key equals the pinned Gate
key when one is given; the request hash; that the passkey's client data has
type `webauthn.get`, the expected challenge, and an origin equal to the
receipt's own `rp.origin`; that the authenticator data starts with the hash of
the receipt's own `rp.id` and has the user-present and user-verified flags;
and that the public key **named in the receipt** verifies the passkey
signature.

What it checks only when asked: that the approver's public key is one the
verifier already knows. Since 1.4.0 a verifier can pin approver passkeys
(`perathos gate trust <receipt>`, the `PERATHOS_GATE_APPROVERS` variable, or
`evidence verify --approver-key`); once any is pinned, a receipt naming any
other passkey is rejected (`ERR_GATE_UNTRUSTED_APPROVER`). With nothing
pinned, which is the default, the only thing tying a public key to a name is
the Gate server's signature. The pin list is a local, unsigned file.

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| An approval replayed for different arguments | Yes | The guard compares the receipt's `args_hash` with the hash of the arguments about to run. |
| An approval replayed as a denial, or for another request | Yes | The challenge binds the decision and the request hash. |
| A receipt altered after signing | Yes | The receipt hash covers every field and is signed by the server. |
| A receipt signed by a different Gate | Yes, when the key is pinned | The guard refuses to use the Gate at all without a pinned key. `gate verify` and `evidence verify` accept an unpinned receipt as internally consistent, and say so: `VALID_UNCONFIRMED_GATE` in both, plus `Gate key UNCONFIRMED` on the approvals line of `evidence verify`. |
| An expired approval | Yes | Rejected at or after `valid_until` (default 10 minutes after the decision), judged by the local clock against a time set by the server. |
| An approval used twice | Partly | The guard marks a used receipt with a local `.used` file in `<project>/.perathos/approvals/`. Anyone who can delete that file can reuse the receipt for the same arguments until it expires. |
| A click without the approver's authenticator | Yes | The server requires a passkey assertion with user verification from a credential enrolled for that organisation, and the verifier re-checks the flags and the signature. |
| A look-alike approval site collecting an approval | Yes, to WebAuthn's origin binding | A passkey is scoped to its relying-party id by the browser and authenticator. The server checks origin and RP id, and the verifier checks them against the receipt. Perathos relies on the browser here. |
| The Gate unreachable, or traffic blocked (A4) | Yes (fails closed) | Any Gate error leaves the guard's denial in place. The cost is availability: the action stays blocked. |
| A network attacker forging an approval (A4) | Yes, after the key is pinned | Receipts are verified against the pinned key, not the connection. `perathos gate login` takes the key from the server over HTTPS on first use; an attacker able to intercept that one connection could have a wrong key pinned. Compare it with a key published or sent separately. |
| The action text not matching what will run | Partly | In the guard path the text is taken from the real arguments, and `args_hash` is checked before running. The server cannot check that the text matches `args_hash`. Anyone holding the organisation API key can post a request with any text and any `args_hash`. That key is stored in `~/.perathos/config.json` on the agent's machine. |
| An agent redirecting the client to its own Gate (A2) | No | The Gate URL and the pinned key are in a local, unsigned configuration file. An agent that can write it can pin a key it controls. Guard patterns deny the obvious routes only. |
| Proving a specific hardware device approved | No | The server requests no attestation. Passkeys may be synced between a person's devices by their passkey provider. The Gate does not claim device binding. |
| Proving which person approved | Partly | A receipt shows that a credential enrolled under a name produced a user-verified assertion. The link from that credential to a person was made at enrolment, by whoever opened the single-use enrolment link. Anyone with control of the approver's passkey account or unlocked device can approve. |
| Requiring a particular approver, or two approvers | No | Any active approver of the organisation can decide any request. |
| An approver deceived into approving (A6) | No | See section 6. |

**A malicious or compromised Gate server (A5).** Checked against
`perathos/gate.py` and the server source.

It can:

- Refuse or delay decisions. The guard then keeps the action blocked.
- Read everything sent to it: the command text (up to 2,000 characters in the
  guard path), the rule id, the host name and the session id. It also holds
  approver names and the organisation's notification webhook URL. The client
  has no option to withhold the command text.
- **Forge an approval that passes verification.** It holds the server signing
  key, and the verifier takes the approver's public key from the receipt. A
  server can generate a key pair, write a receipt naming any approver, sign the
  WebAuthn part with its own key and sign the receipt. With no approver
  passkeys pinned (the default), nothing in `perathos` detects this. The forged
  receipt carries a public key that differs from the real approver's, so a
  client or reviewer that has pinned the real approvers' passkeys (1.4.0:
  `perathos gate trust`, `PERATHOS_GATE_APPROVERS`, `evidence verify
  --approver-key`) rejects it. The pins must have been taken from receipts or
  an enrolment record that the forger did not also control.
- Enrol a new passkey under any name, with the same effect.
- Show an approver one action while asking their passkey to sign the challenge
  for another. The approver's device signs a hash; the person sees whatever
  page the server sends.

It cannot:

- Produce a signature under a passkey that a real approver already enrolled.
- Cause a command to run on its own. It only answers requests the agent side
  makes. A forged approval matters only for a command the agent has already
  tried and the guard has blocked.
- Get a different command run under an approval. The guard checks `args_hash`
  against the real arguments locally.
- Alter flight-recorder logs, sign checkpoints, or sign preconditions. It holds
  none of those keys.

Running your own Gate changes who holds the server key. It does not change
the structure: whoever controls the server key can forge approvals for the
clients that pin it.

**The hosted Gate** at `gate.perathos.com` is a single small deployment run by
the maintainer. It has no availability commitment, and there is no third-party
audit of it to point to. It stores the action text of every request sent to it. Treat it as
suitable for trials, and treat an outage as "guard-blocked actions stay
blocked until a person signs a precondition".

### 5.8 Proof bundles (the original layer)

A proof bundle binds one AI output to its digest, verifier verdicts, a model
identifier and an optional signature. Two properties must not be conflated:
**attestation integrity** (the bundle cannot be altered undetected;
cryptographic) and **detection quality** (how good the verifiers are;
statistical, and not a guarantee).

| Threat | Protected? | Mechanism, or why not |
|---|---|---|
| Editing the output digest, verdicts, model identifier or timestamps | Yes | Every field is folded into `integrity_hash`; `bundle_id` is derived from it; verification recomputes. |
| Editing, adding or removing the verification block | Yes | `verification_hash` is in the integrity payload if and only if verification is present (`ERR_INTEGRITY_HASH_MISMATCH`). |
| Forging a signature on an intact chain | Yes | Ed25519 signature checked when present (`ERR_BAD_SIGNATURE`). Unsigned bundles fail by default. |
| Algorithm confusion | Yes | Any algorithm other than `ed25519` is rejected (`ERR_UNSUPPORTED_ALGORITHM`). |
| Signature or serialisation malleability | Yes | Strict lowercase hex; deterministic canonical JSON. |
| A malformed bundle crashing the verifier | Yes | `verify_bundle` returns `ERR_MALFORMED_BUNDLE`; `inspect` is type-guarded; verifiers degrade to `INCONCLUSIVE`. |
| A torn bundle file after a crash | Yes | Atomic writes (temporary file, fsync, `os.replace`). |
| Stripping a signature and re-signing with another key | Partly | Detected only when the consumer pins a key (`--verify-key`) or a trust set (`--trust-jwks`). |
| A wrong verdict | No | A `PASS` means the configured verifiers found no problem in the evidence they were given. Detection has false negatives. `INCONCLUSIVE` is not `PASS`. Verifier quality is bounded by the evidence, the resamples and the NLI model supplied. |
| A false model identifier | No | The identifier binds a claimed descriptor. Showing which weights ran needs attestation of the execution environment, which is out of scope. |
| Reading a bundle's content | No | Bundles are not encrypted. |
| A false `issued_at` | No | Self-asserted. RFC 3161 anchors apply to recorder checkpoints, not to bundles. |

## 6. What each adversary can still do

**A1, a careless agent.** Stopped when its command matches a guard rule and no
approval covers it. Not stopped when the destructive command is one the rules
do not describe, when hooks are not installed, or when a broad or long-lived
precondition (scope `*`, a long `--ttl`) happens to cover it.

**A2, a hostile agent on the same machine.** With the default set-up it can:
disguise a command past the guard; read the local signing key by a route the
patterns do not name, then forge checkpoints and preconditions; edit the
approver list, the Perathos configuration or project-level hook files; work
through a channel the hooks do not see. With every item in section 8 in place
it is left with: disguising commands past the guard (always), and asking the
recorder's remote signer for signatures if it can reach the signing
credential. Perathos does not contain a hostile agent. Use operating-system
isolation for that.

**A3, a tamperer after the fact.** Without the signing key: cannot change
sealed receipts undetected; can remove the unsealed tail; can delete whole
logs; can cut a log back to an earlier checkpoint if they also remove the head
witness and no anchor copy is held elsewhere. With the signing key: can
replace a log with a different valid one, except where an off-machine anchor
already fixes a checkpoint.

**A4, a network attacker.** Can stop anchoring (checkpoints stay signed but
unanchored) and can stop Gate approvals (actions stay blocked). Cannot forge
an anchor or, once the Gate key is pinned, an approval. Recording with a local
key, the guard's pattern matching and offline verification make no network
calls. A remote signer, anchoring and the Gate do.

**A5, a malicious Gate.** See 5.7. In short: unless the client has pinned its
approvers' passkeys, it can approve, on its own authority, any blocked action
that an agent attempts, and the receipt will verify.

**A6, a phished or pressured approver.** The passkey proves that an enrolled
credential approved a request. It does not prove the approver read it,
understood it, or was not misled. Routes that work: an agent or a person who
words a request to look routine; a stream of requests that trains the approver
to tap approve; an approve link forwarded with a reassuring message; takeover
of the approver's passkey provider account or unlocked device. Origin binding
stops look-alike sites. It does not stop a real request that is wrongly
approved. The approve link also lets anyone who holds it read the action text.

## 7. Residual risks and roadmap

Stated plainly, in rough order of weight:

1. The guard is a pattern matcher and not a sandbox.
2. With the default local key, an agent that can read the key can forge both
   records and approvals.
3. A period with hooks switched off leaves an invisible gap. A recording
   failure leaves a gap in the log that only a local, unsigned error log
   (`~/.perathos/errors.log`) notes; a third party cannot see it.
4. Completeness is never proven: only what the hooks saw is recorded.
5. Signer identity rests on a pin the verifier must obtain out of band, and
   so do the Gate key and the approver passkeys. Unpinned results say so
   (`VALID_UNCONFIRMED_SIGNER`, `VALID_UNCONFIRMED_GATE`, `Gate key
   UNCONFIRMED`, `approvers NOT PINNED`), and they still exit 0: a reviewer
   who does not read the output, or does not obtain the keys, learns only
   that the pack is internally consistent.
6. Whoever controls the Gate server key can forge approvals for any client or
   reviewer that has not pinned approver passkeys. Pinning is optional and off
   by default.
7. The approver list, the Gate pin and the signer setting are unsigned local
   files.
8. A remote recorder signer keeps the key from being copied. It does not keep
   a process with the signing credential from using it.
9. Times are local-clock unless anchored, and an anchor is an upper bound.
10. The `model` field is self-reported.
11. Preconditions are reusable until expiry and are not bound to a session.
12. Synced passkeys do not prove a specific hardware device, and the Gate does
    not claim device binding. An approver can be socially engineered.
13. The MCP proxy relays, unguarded and unrecorded, any line it cannot parse
    as JSON. (It no longer forwards a call when the guard raises: that now
    fails closed.) The browser verifier does not check Gate approvals.
14. The hosted Gate is a single small deployment.
15. One maintainer. No penetration test by an accredited firm
    ([SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md), section L).

Built since this list was first written: verifier-side pinning of approver
passkeys (1.4.0); a Gate key and approver pins in `evidence verify`, with the
cross-check of cited approvals; a fail-closed guard in the MCP proxy; a marker
on checkpoints the signer failed to sign; a local log of recording failures.

Not built yet (none of these is a commitment): Gate receipt checks in the
browser verifier; a check of an approval's validity window against the call's
time in `evidence verify`; a tamper-evident record of recording failures;
single-use or session-bound preconditions; a transparency log for checkpoints
or receipts; attestation of the execution environment; binding key id and
expiry into signed payloads for rotation. See
[ROADMAP_2.0.md](ROADMAP_2.0.md).

## 8. Deployment requirements for the stronger properties

Each row is something the operator must do. Perathos cannot do it for them,
and `perathos doctor --recorder` reports on several of them.

| To get this | Do this | Without it |
|---|---|---|
| Records the agent cannot forge by reading a file | Use a **remote signer** for checkpoints (`perathos config signer vault:... \| gcpkms:... \| command:...`), and keep the signing credential as far from the agent as the hook allows. Log and alert on signer use. | An agent that reads `signing.key` can seal any log. |
| Approvals the agent cannot forge | List **approvers** (`perathos approvers add`) whose keys are held off the machine or on a device the agent's user cannot use. Do not list the recorder key. | The recorder key approves destructive actions. |
| Trust lists the agent cannot edit | Make `~/.perathos/` (at least `approvers.json` and `config.json`) and the hook files unwritable by the user the agent runs as, or run the agent as a different user. | The guard's path patterns are the only protection. |
| No silent hook removal | Install **managed hooks** (`perathos hooks install --scope managed --guard --anchor`) on Claude Code, and do not give the agent administrator rights. | The agent can edit project or user hook files by a route the guard does not name. |
| A missing guard blocks rather than allows | Keep the installer's fail-closed settings, and use an agent tool version that honours them. | A broken hook lets calls through. |
| Detection of a cut-off or rewritten log | Keep **off-machine anchor copies**: set `perathos config anchor_mirror <path>` to a location the agent and the machine's users cannot change, and verify with `--anchors <copy>` and `--require-anchor`. | Truncation after the last surviving checkpoint is undetectable to someone who also deletes the head witness and the local anchors. |
| Independent time | Turn anchoring on (`--anchor`, needs `perathos[anchor]` and network). | All times are the local clock. |
| Signer identity on verification | **Pin the signer on verify**: `--verify-key <hex>` or `--trust-jwks`, with the key obtained through a separate channel. Treat `VALID_UNCONFIRMED_SIGNER` as "consistent, origin unknown". | Anyone can produce a self-consistent log or pack. |
| Gate receipts from the right server | **Pin the Gate key**, and confirm the key that `perathos gate login` pinned against one obtained separately. Check pack approvals with `perathos evidence verify --gate-key` (or one receipt with `perathos gate verify --gate-key <hex> --approver-key <key>`). | A receipt signed by any key passes as internally consistent. |
| A check on the Gate itself | **Pin your approvers' passkeys** (`perathos gate trust <receipt>` after each enrolment, or `PERATHOS_GATE_APPROVERS` in CI), keep your own record of each approver's public key from enrolment, and give reviewers those keys for `evidence verify --approver-key`. Prefer a Gate you run for anything that matters. | Whoever holds the Gate key can name any approver. |
| Notice of recording faults | Run `perathos doctor --recorder` regularly and look at `~/.perathos/errors.log`; treat a `signer_error` checkpoint or a logged recording failure as an incident for that session. | A failed hook or signer leaves a gap nobody looks at. |
| Approvals that mean something | Keep the approver group small. Tell approvers to read the command text and to deny anything they did not expect. Keep request volume low enough that each one is read. | Approval fatigue makes the passkey a formality. |
| Narrow preconditions | Name the specific resource in `--scope`, keep `--ttl` short, avoid `*`, and use checks that test the safeguard. Review `check` text in audits. | One precondition covers many commands for its whole lifetime. |
| Containment of a hostile agent | Operating-system isolation: a separate user, a container or VM, scoped credentials, no production secrets in the agent's environment. | Nothing in Perathos confines the agent. |

## 9. Cryptographic choices

- **Hash:** SHA-256.
- **Signatures:** Ed25519 (the `cryptography` library) for checkpoints,
  preconditions, pack manifests, bundles and Gate server signatures. Passkey
  signatures in Gate receipts are verified as ES256, EdDSA or RS256.
- **Timestamps:** RFC 3161, verified against pinned roots (needs the
  `rfc3161-client` extra).
- **Serialisation:** deterministic canonical JSON (sorted keys, compact
  separators, UTF-8, NaN and Infinity rejected, string keys only), so that
  another implementation reproduces the same bytes.

These are standard primitives used in a standard way. The construction has
had internal review and an independent red-team of 1.0.0
([SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md), section L), not a formal
cryptographic audit.

## Related documents

- [SECURITY.md](../SECURITY.md): how to report a vulnerability, and what is in
  scope.
- [FOR_AUDITORS.md](FOR_AUDITORS.md): how to check an evidence pack.
- [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md): vendor questionnaire.
- [ENTERPRISE_FAQ.md](ENTERPRISE_FAQ.md): procurement questions on the
  proof-bundle layer.
- Specifications: [RECEIPT_V1](specs/RECEIPT_V1.md),
  [PRECONDITION_V1](specs/PRECONDITION_V1.md), [GATE_V1](specs/GATE_V1.md),
  [BUNDLE_V2](specs/BUNDLE_V2.md).
