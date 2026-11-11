# Vendor security assessment: Perathos

A pre-filled vendor security questionnaire for a buyer's security, privacy and
procurement teams, laid out like a SIG Lite / CAIQ Lite response. Every answer
was checked against the source code in this repository at the time of
writing; where an answer rests on something other than the code, the row says
so. File references are to this repository.

| | |
|---|---|
| Product | Perathos, open-source flight recorder for coding agents (`pip install perathos`) |
| Version assessed | 1.1.0 (PyPI), plus the unreleased changes on `main` listed in [CHANGELOG.md](../CHANGELOG.md) |
| Licence | MIT ([LICENSE](../LICENSE)) |
| Source | <https://github.com/perathos-protocol/perathos> (public) |
| Security contact | hello@perathos.com, subject starting `SECURITY:` ([SECURITY.md](../SECURITY.md)) |
| Date | 2026-11-05 |

**Certifications and attestations.** Perathos holds no SOC 2 report, ISO 27001
certificate or other third-party certification, and nothing in this document
is a compliance claim. [CONTROL_MAPPING.md](CONTROL_MAPPING.md) describes which
of *your* controls the artefacts Perathos produces can serve as evidence for.

---

## A. Product and deployment profile

| Question | Answer |
|---|---|
| What is the product? | A Python package and CLI that runs on the developer's or CI machine. It records every coding-agent tool call (Claude Code, Cursor, any MCP client) as a hash-chained, signed receipt, blocks destructive commands unless a person has signed a safety precondition, and exports evidence packs that a third party can verify offline. |
| Is it SaaS / vendor-hosted? | The recorder, guard, preconditions and evidence packs are not: they run entirely in the customer's environment with no Perathos server or account. Perathos Gate (optional passkey approvals) is a server component: open source and self-hostable, or the vendor-hosted instance at `gate.perathos.com`, which then receives the text of each action sent for approval. |
| Does the vendor have access to customer systems or data? | No. Nothing is sent to the vendor (see section C). Optional professional services (installation and configuration) would be performed under a separate engagement, on the customer's terms. |
| Deployment model | `pip install perathos` (optionally `perathos[anchor]`), `perathos keygen`, `perathos hooks install --guard --anchor`. Hooks can be installed per project, per user, or into Claude Code's managed policy file (`--scope managed`). |
| Supported platforms | Python 3.11+ on Linux, macOS and Windows. CI tests Python 3.11, 3.12 and 3.13 on all three (`.github/workflows/ci.yml`). |
| Who maintains it? | A single maintainer (the `perathos-protocol` GitHub organisation). This is the main vendor risk; it is mitigated by the MIT licence, the public source, public file-format specifications and two independent verifier implementations, so a customer can fork, audit, or re-implement verification without the vendor (see section I). |

## B. Data handling and privacy

| Question | Answer |
|---|---|
| What data does Perathos read? | The hook payload the agent tool passes on stdin (tool name, arguments, result); the tail of the agent's local transcript file, only to find the model name (`recorder._model_from_transcript`); and, when the guard is on, the contents of a script file a command is about to run (up to 1 MiB) so it can be scanned for destructive commands (`guard._scan_script_files`). |
| What data does Perathos store? | Receipts: tool name, tool-call id, status, timestamp, sequence number, chain hashes, and **SHA-256 hashes** of the tool arguments and results (`args_hash`, `result_hash`). Tool arguments and outputs are **never written**, only their hashes (`recorder.record_hook_event`, `integrations/cursor.py`, `mcp_proxy.py`). Checkpoints add the self-reported model name and the signer's public key. Guard decisions add a rule id and a precondition hash, not the command text. |
| Is any content stored in cleartext? | Yes, in two places a person controls: a precondition stores its `scope`, the `check` command (for example `pg_restore --list backups/prod.dump`) or the `manual_reason` text, and a hash of the check's output (`guard.create_precondition`). Evidence packs include those preconditions and a report of counts and rule ids. Do not put secrets in a check command line. |
| Where are files written? | `<project>/.perathos/sessions/<session>.jsonl` and `.head.json` (receipt logs); `<project>/.perathos/preconditions/*.json`; `~/.perathos/keys/` (`signing.key`, `verify.key`); `~/.perathos/anchors/<session>.jsonl` (timestamps); `~/.perathos/errors.log` (recording failures, section J); `<project>/.perathos/approvals/` (Gate approval receipts, if the Gate is used); `~/.perathos/bundles/` (proof bundles, if that feature is used); the directory given to `perathos session export --out` (evidence packs). Hook configuration goes to `.claude/settings.json`, `.cursor/hooks.json` or the Claude Code managed settings file, depending on `--scope`. |
| Can a stored hash leak data? | A hash cannot be reversed, but a short or guessable value (a yes/no answer, a small number, a known file) can be confirmed by hashing guesses. This is documented in [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md). |
| Is personal data processed? | Not by design. Receipts hold hashes and tool names. A precondition's free-text fields and the OS username in file paths could contain personal data if a person types it there. |
| Encryption at rest | Not applied by Perathos. Logs are tamper-evident, not encrypted; the signing key is stored as cleartext hex protected by file permissions. Use disk encryption or your secrets store as you would for any local credential. |
| Data retention and deletion | Files stay where they are written until the customer deletes them. Perathos has no retention policy of its own and no remote copy. |
| Data residency | Wherever the customer runs it. The only outbound data is described in section C. |

## C. Network egress and telemetry

Checked by searching the package for network code (`urllib`, `requests`,
`httpx`, `http.client`, `socket`, `aiohttp`, `urlopen`, `fetch`; re-checked
2026-11-10). Network calls in `perathos/` are made from four places, each
only when the customer has configured that feature:

1. `anchor.request_timestamp`: the RFC 3161 request to the Time Stamping
   Authority (anchoring).
2. `gate.GateClient`: HTTPS calls to the configured Perathos Gate server
   (creating an approval request, polling its status, reading the server's
   public key at `perathos gate login`).
3. `signers.vault_signer`: HTTPS calls to the configured HashiCorp Vault
   (reading the public key, requesting a signature).
4. `signers.gcpkms_signer`: calls to Google Cloud KMS through the
   `google-cloud-kms` client library (same two operations).

A `command:` signer runs the customer's own program, which may make network
calls of its own. `gate.py` also calls `socket.gethostname()`, a local lookup,
to put the host name in an approval request.

| Question | Answer |
|---|---|
| Does Perathos make network connections by default? | No. With the default local signer and no anchoring or Gate configured, recording, the guard, preconditions, verification and evidence export are fully offline. |
| What leaves the machine with a remote signer? | Only when the customer configures `vault:` or `gcpkms:` as a signer: the SHA-256 hash to be signed (a checkpoint, manifest or precondition hash) and the customer's own credential for that service, sent to the customer's own Vault or Google Cloud KMS. No content is sent. |
| What leaves the machine when the Gate is configured? | Only when the customer runs `perathos gate login` and the guard blocks a call: an approval request to the configured Gate server holding the action text (the command, up to 2,000 characters), the rule id, a hash of the arguments, the agent name, the session id and the host name, authenticated with the organisation API key. The Gate server therefore sees the text of every action sent for approval; see section A on who hosts it. |
| What leaves the machine when anchoring is enabled? | Only when the customer opts in (`perathos hooks install --anchor` or `perathos session anchor`): an RFC 3161 timestamp request containing the SHA-256 hash of a checkpoint and a random nonce, sent over HTTPS to the Time Stamping Authority. Default TSA: `https://freetsa.org/tsr`; `perathos session anchor --tsa-url` selects another. No content, file names, user or machine identifiers are sent by Perathos (the TSA sees the requesting IP address, as any HTTPS server does). Responses are accepted only if they chain to a pinned TSA root shipped in the package. |
| What does the MCP proxy connect to? | `perathos mcp-proxy` starts the MCP server command the customer configures, as a child process, and relays JSON-RPC over stdin/stdout (`mcp_proxy.py`, `subprocess.Popen`). It opens no sockets itself; any network traffic is the configured server's own. |
| Telemetry, analytics, crash reporting, update checks | None. There is no telemetry code in the package. |
| Optional components with egress | The `nli` extra (Claim-Entailment verifier for proof bundles, not used by the flight recorder) loads `cross-encoder/nli-deberta-v3-xsmall` through Hugging Face `transformers`, which downloads the model from the Hugging Face Hub on first use unless it is already cached. |
| Website and browser verifier | The site (`site/`) is static, sets no cookies and includes no analytics. The browser verifier reads an evidence pack the user selects, in the browser; its Content-Security-Policy is `connect-src 'self'`, and the only fetch is the bundled sample pack. Its one third-party script is loaded from a CDN with a Subresource Integrity hash. |

## D. Application security and secure development

| Question | Answer |
|---|---|
| Source code availability | Public, MIT-licensed. Customers may audit, fork and build from source. |
| Change process | Changes land on `main` through pull requests with CI. Branch protection on `main` blocks force pushes and branch deletion and requires the CI lint check, and the repository has one collaborator with write access. Two LLM automation workflows that could open pull requests (`agents.yml`, `ci-fixer.yml`) are disabled in GitHub Actions; neither is part of the build or release path. |
| Automated testing | `pytest` on 3 operating systems x 3 Python versions on every push and pull request to `main`; `ruff` lint; the browser verifier is tested in CI against the Python implementation. |
| Security regression tests | `tests/test_guard_hardening.py` (guard bypass corpus of 228 commands, all blocked, including the "unresolvable" class; lists of commands that must stay allowed; script and write scanning, scope matching, fail-closed installs), plus tamper tests for receipt chains, checkpoints, anchors and evidence packs (`tests/test_recorder.py`, `tests/test_anchor_guard.py`, `tests/test_evidence.py`, `tests/test_audit_fixes.py`). |
| Static analysis / dependency alerts | `ruff` in CI. Dependabot alerts and security updates, GitHub secret scanning with push protection, and private vulnerability reporting are enabled on the repository (from 1.2.0). |
| Input handling | Hook payloads, logs, bundles and packs are treated as untrusted: malformed input yields an error result rather than a crash (`verify_session`, `verify_evidence_pack`, which also rejects unsafe paths inside a zip). |
| Fail-safe behaviour | Hooks are installed fail-closed: `onFailure: "block"` on the Claude Code guard hook and `failClosed: true` on Cursor's, so if the hook process is missing or fails, the agent tool blocks the call. Inside the hook, a deny decision is emitted even if recording the receipt fails. Since 1.2.0 this also holds inside the hook: if the guard's own rule evaluation raises an unexpected exception, the call is denied with rule `guard.error` and recorded as a denial (Claude Code and Cursor). The MCP proxy with `--guard` behaves the same way from the release after 1.4.1: if the guard raises, the client gets a tool result with `isError: true` saying the guard failed, the call is recorded as denied (`guard.error`) and it is never forwarded to the server; in 1.4.1 and earlier the proxy logged the error and forwarded the call. Calls inside a JSON-RPC batch are guarded one by one, and a `tools/call` sent as a notification (no `id`) is guarded too and dropped when denied. Without `--guard` the proxy only records and relays. The proxy is not a fail-closed boundary in one respect: a line it cannot parse as JSON is relayed untouched and unrecorded. Recording itself never blocks: if a hook cannot write a receipt, the call proceeds, the error goes to stderr and a line is appended to `~/.perathos/errors.log` (see section J). With `--scope managed`, `allowManagedHooksOnly: true` stops the agent adding, removing or editing hooks. |

## E. Cryptography and key management

| Question | Answer |
|---|---|
| Algorithms | SHA-256 for hashing; Ed25519 signatures (pyca `cryptography`); RFC 3161 timestamps; deterministic canonical JSON (sorted keys, no whitespace, UTF-8, NaN/Infinity rejected) so any implementation reproduces the same bytes. Signatures declaring any algorithm other than Ed25519 are rejected. |
| Where is the signing key? | `~/.perathos/keys/signing.key`, cleartext hex, written atomically; `0o600` on POSIX, owner-only ACL via `icacls` on Windows (best-effort, with a warning if it fails) (`storage.py`). |
| Is the key protected from the agent? | Partly. The guard denies agent commands and file-tool calls that mention `signing.key` or `.perathos/keys`, and agent attempts to run `perathos keygen` or `perathos precondition`. An agent with unrestricted shell access could still reach a key file on the same machine by a route the patterns do not catch; for real separation, keep the key where the agent's OS user cannot read it. |
| Remote / KMS signing | Since 1.2.0, checkpoints, evidence-pack manifests and preconditions can be signed by a key that never touches the agent's machine: HashiCorp Vault transit (`vault:`), Google Cloud KMS Ed25519 (`gcpkms:`), or any HSM, YubiKey or signing service wrapped by a small program (`command:`). Every remote signature is verified against the public key before use. Separate approver keys (`perathos approvers add`) mean the recorder key cannot approve destructive actions. `perathos doctor --recorder` reports whether the recorder key is local and whether approvers are separate. |
| How is a signer's identity established? | By pinning: verifiers accept `--verify-key <hex>` (or `--trust-jwks` for a published key set). Without a pinned key, `session verify` and `evidence verify` report `VALID_UNCONFIRMED_SIGNER` rather than `VALID`. |
| Rotation and revocation | `perathos keygen` creates a new key; old logs stay verifiable with the old public key. There is no built-in revocation service. |
| Time source | Receipt and precondition times come from the local clock. Anchored checkpoints carry an independent RFC 3161 time. |

## F. Supply chain and third-party components

| Question | Answer |
|---|---|
| Runtime dependencies | Two: `click>=8.0` and `cryptography>=42.0` (which brings `cffi` and `pycparser`). Lower bounds only, as is usual for a library; pin them in your own lock file. |
| Optional extras | `anchor` (`rfc3161-client>=1.0.9,<2`), `schema` (`jsonschema`), `mcp` (`mcp>=1.0,<2`), `nli` / `train` (`transformers`, `torch` and training tools), `agents` (repository automation only; not used by the package). None is installed by a bare `pip install perathos`. |
| How are releases built and published? | By GitHub Actions from a pushed version tag (`.github/workflows/release.yml`): build sdist and wheel, smoke-test the wheel in a clean virtualenv, publish to PyPI with **PyPI trusted publishing** (OIDC; no long-lived API token exists). |
| Build provenance | From the first release after 1.1.0: a GitHub build provenance attestation (Sigstore-signed, SLSA provenance) for the sdist, the wheel and the SBOM. Verify with `gh attestation verify perathos-<version>-py3-none-any.whl -R perathos-protocol/perathos`. Releases up to and including 1.1.0 have no attestation. |
| SBOM | From the first release after 1.1.0: a CycloneDX JSON SBOM (`perathos-<version>.cdx.json`) of the wheel and its resolved runtime dependencies, generated from a clean virtualenv containing only the wheel, attached to the GitHub Release for the tag. |
| Third-party services in the trust base | None for recording and verification. With anchoring on, the chosen TSA (default freetsa.org) is trusted for time only; its root is pinned. |

## G. Vulnerability management and incident response

| Question | Answer |
|---|---|
| How are vulnerabilities reported? | Email hello@perathos.com with a subject starting `SECURITY:`, or use GitHub private vulnerability reporting on the repository; see [SECURITY.md](../SECURITY.md), which also covers scope and safe harbour. There are no bug bounty payments. |
| Response targets | Acknowledge within 5 working days; initial assessment within 10 working days of the acknowledgement. These are targets of a single-maintainer project, not a contractual SLA. |
| Disclosure policy | Coordinated disclosure; by default 90 days after the report or when a fix is released, whichever is first. Reporters are credited unless they ask not to be. |
| Supported versions | The latest 1.x release. Fixes ship as new 1.x versions; older minors are not patched. |
| How are customers notified? | Through the CHANGELOG, GitHub Releases and PyPI. There is no customer list or mailing list. |
| Security advisories history | The 1.1.0 release fixed about thirty guard bypasses found by a red-team of 1.0.0 (section L). No other advisories have been issued. |

## H. Access control

| Question | Answer |
|---|---|
| User accounts, SSO, MFA, RBAC | Not applicable: there is no service to log into. Access to logs and keys is governed by the customer's OS file permissions. |
| Segregation of duties | Built into the guard: a destructive command needs a precondition signed by a person with the key, created outside the agent session; the agent is denied creating its own (`guard.SELF_AUTH_RULES`). |

## I. Business continuity and vendor risk

| Question | Answer |
|---|---|
| What happens if the vendor stops maintaining it? | Installed versions keep working; nothing depends on a vendor service. The code is MIT-licensed and can be forked. |
| Can evidence be verified without Perathos? | Yes. The receipt, anchor and precondition formats are public ([specs/RECEIPT_V1.md](specs/RECEIPT_V1.md), [specs/PRECONDITION_V1.md](specs/PRECONDITION_V1.md)) and use only SHA-256, Ed25519, canonical JSON and RFC 3161. Two independent implementations exist (Python CLI and the browser verifier in `site/verify/`). |
| Escrow | Not needed: the source is public. |

## J. Logging and monitoring

| Question | Answer |
|---|---|
| What does Perathos log about itself? | Hook errors are printed to the agent tool's stderr. From the release after 1.4.1, each recording failure (a receipt that could not be written, a signer that could not seal a checkpoint) also appends one JSON line to `~/.perathos/errors.log` (time, component, exception type and message, session id, project path); `perathos doctor --recorder` and `perathos session verify` report the count. The file is local, unsigned and writable by the agent's user: a diagnostic for the operator, not evidence. A checkpoint whose signer failed is written unsigned with `signer_error` in its hashed body, and fails verification with `ERR_UNSIGNED`. |
| Integrity of its records | Each receipt includes the previous receipt's hash; checkpoints are Ed25519-signed at the end of each turn and session; a head witness file and optional RFC 3161 anchors make truncation detectable. `perathos session verify` reports edits, deletions, insertions, reordering and truncation. |
| SIEM integration | None built in. Logs are JSON Lines; deny decisions are receipts with `guard.decision: "deny"` that a SIEM can ingest. |

## K. Threat model summary and honest limits

Full model: [THREAT_MODEL.md](THREAT_MODEL.md) (rewritten 2026-11-10 to cover the recorder, guard, hooks, signers, evidence packs and the Gate; where it differs from this document it is the more recent and more detailed statement), [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md) ("What a valid log proves, and what it does not") and [FOR_AUDITORS.md](FOR_AUDITORS.md).

| Question | Answer |
|---|---|
| What does a valid record prove? | That the holder of the signing key sealed this exact sequence of receipts, and nothing up to the last checkpoint was edited, removed, inserted or reordered since; with anchors, that each checkpoint existed by the TSA's time. Whoever holds an original argument or output can show it matches its hash. |
| Is the guard a sandbox? | No. It matches command patterns (after stripping quotes and SQL comments, and scanning scripts the command runs). It stops accident-class destructive commands. Commands whose text does not say what will run are flagged as "unresolvable" and need a precondition or approval like a destructive command: a variable or substitution in command position, `eval` / `iex` of one, `cmd /c %X%`, and a download handed to an interpreter (`curl ... \| sh`, `iwr ... \| iex`). That narrows environment-variable indirection and downloaded scripts; it does not close them. A deliberately hostile agent can still disguise a command, for example by assembling the program name (`r${Z}m -rf build`), using an alias or symlink, putting the indirection inside interpreter code, going through a build tool (`make clean`), or generating a script and running it in the same call; and variable indirection is judged only on a shell command line, not inside script files or MCP tool arguments. These known-open forms are kept as a test (`KNOWN_OPEN` in `tests/test_guard_hardening.py`). Run agents with least privilege as well. |
| Can the agent forge records or approvals? | Not without the signing key. With the default local key, an agent able to read it could. With a remote signer for checkpoints (1.2.0) the agent cannot copy the recorder key, but it may still be able to **use** it: the hook has to sign without a person present, so the credential that authorises signing (for example `VAULT_TOKEN`, or Google application default credentials) is normally available to the same OS user the agent runs as, and an agent that can use that credential can have a forged checkpoint signed. What the remote signer adds is that the key cannot be exfiltrated and that its use can be logged, limited and revoked on the signer's side. Approvals are different: an approver signs by hand, so with listed approvers whose keys are held where the agent's user cannot use them, the agent cannot sign a precondition. Perathos cannot check where either credential is kept. See section E and [THREAT_MODEL.md](THREAT_MODEL.md) section 5.5. |
| Which model ran? | Not proven. The `model` field is self-reported by the agent tool's transcript. |
| Can gaps in recording be hidden? | A period where hooks were switched off is not visible in the log, and neither is a receipt a failing hook could not write (that is noted only in the local `~/.perathos/errors.log`, section J). Installing hooks in the managed policy file (`--scope managed`), which the agent cannot edit, is the mitigation. |
| Can the end of a log be cut off? | Detectable when the head witness survives, or when a copy of the anchors file is kept where the agent cannot reach it; otherwise a cut after the last checkpoint is not detectable. |
| Times | Local clock unless the checkpoint is anchored. |
| Preconditions | Prove that a named check ran and exited 0, signed by the key holder. Whether the check meaningfully tests the safeguard is the signer's judgement. A precondition can be relied on repeatedly until it expires. |

## L. Independent testing

| Question | Answer |
|---|---|
| Has the product been independently tested? | Version 1.0.0 was red-teamed independently before 1.1.0. The red-team found about thirty accident-class commands that the guard let through (recursive deletes in several shells, destructive git and SQL variants, interpreter one-liners, quote-obfuscated commands, scripts that contained destructive commands, writes to the hook configuration). All were fixed in 1.1.0, and the bypass list is now a permanent regression test, `tests/test_guard_hardening.py` (since grown to 228 commands; the additions were written by the maintainers, not by an independent tester). The red-team's attempts to tamper with recorder logs, evidence packs and anchors were all detected. |
| Is the red-team report available? | The report itself is not published in the repository; its bypass list is, as the regression test above, and the fixes are listed in the 1.1.0 CHANGELOG entry. |
| Penetration test by an accredited firm | None. |

## M. Compliance and legal

| Question | Answer |
|---|---|
| Certifications (SOC 2, ISO 27001, etc.) | None held. |
| Does using Perathos make us compliant with AIUC-1, SOC 2, the EU AI Act? | No. It supplies evidence for specific controls; [CONTROL_MAPPING.md](CONTROL_MAPPING.md) gives coverage and gaps per control, notably AIUC-1 D003.4 (human approval for destructive operations) and E015.4 (log integrity). |
| Licence obligations | MIT: keep the copyright and licence notice. Core dependencies are permissively licensed (BSD, Apache-2.0, MIT); the SBOM lists them per release. |
| Warranty | As provided by the MIT licence ("as is", no warranty). Commercial terms, if any, are agreed separately. |
