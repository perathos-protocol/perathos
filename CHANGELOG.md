# Changelog

All notable changes to Perathos. Pre-1.0: pin a commit SHA for reproducibility.
This project aims to follow [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.4.0] - 2026-11-10

### Security
- **Approver pinning for Gate receipts.** A receipt carries the approver's public
  key, and until now nothing checked that key against one the verifier knew, so
  whoever held the Gate server's signing key could issue a receipt naming an
  approver key of their own and it would verify. `perathos gate trust RECEIPT`
  pins an approver's passkey; once any is pinned, the guard, `require_approval()`
  and `perathos gate verify` reject approvals from every other passkey
  (`ERR_GATE_UNTRUSTED_APPROVER`). `perathos gate approvers` lists and unpins.
  `gate verify` now says whether the approver is pinned. Not yet covered:
  `evidence verify` still checks approvals without pins. The pin list is a local
  unsigned file, so it protects against the Gate server, not against an agent
  that can edit the file.

### Fixed (docs)
- GATE_V1.md, README and the security assessment no longer say a compromised
  Gate server cannot forge an approval, that passkeys are hardware-backed, that
  the client can withhold command text, or that there is no server component.

### Added
- `perathos gate request` shows the approve link as a QR code when run in a
  terminal with the `qr` extra installed (`pip install "perathos[qr]"`), so the
  approver scans it instead of retyping a link that carries a token. `--qr` /
  `--no-qr` force it on or off; `--qr-file PATH` saves it as `.png` or `.svg`.
- Guard: an "unresolvable" rule class for commands whose text does not say
  what will run. `unresolvable.indirect` covers a variable or substitution in
  command position (`$CMD -rf build`, `$(echo rm) -rf x`), `eval "$X"`,
  `bash -c "$PAYLOAD"`, text piped into a shell, PowerShell `iex $x`, `& $cmd`
  and `-EncodedCommand`, and `cmd /c %X%`. `unresolvable.remote-script` covers
  a download handed to an interpreter (`curl ... | sh`, `iwr ... | iex`,
  `bash <(curl ...)`, `python -c "$(curl ...)"`, download then run). They are
  denied unless a precondition or approval covers them, like any destructive
  command. Variables and substitutions as arguments, `FOO=bar make`,
  `$HOME/bin/tool`, `eval "$(ssh-agent -s)"` and `curl -o file url` stay
  allowed. Variable indirection is judged only on a shell command line, not
  inside script files or MCP arguments; the forms that still pass are listed
  in the README and kept as a test (`KNOWN_OPEN`).
- Guard rules for accident-class commands that passed before:
  `git push origin +main` / `--delete main` / `:main`, `git checkout -f`,
  `gh repo delete`, `docker compose down -v`, `mkfs`, `rsync --delete`,
  `helm uninstall`, `az group delete`, `gcloud projects delete`,
  `aws s3api delete-bucket`, `aws cloudformation delete-stack`.
- `tests/test_guard_hardening.py`: the bypass corpus grows from 43 commands
  (41 from the red-team) to 148, all blocked, with 68 new commands that must
  stay allowed.

### Changed
- Commands that used to run unremarked may now be denied by the guard: the
  forms above, plus `if $FLAG; then`, `psql -c "$SQL"`, `source $FILE` and a
  downloaded binary run in the same command. Write the command out literally,
  or add a precondition.

### Docs
- `docs/THREAT_MODEL.md` rewritten to cover the whole product, not only proof
  bundles: flight recorder, anchors, guard and preconditions, hooks and the MCP
  proxy, remote signers and approver keys, evidence packs, and Perathos Gate
  (client and server). Adds trust boundaries, six adversaries, a "threat /
  protected? / mechanism" table per component, residual risks, and the
  deployment steps needed for the stronger properties. It states what a
  compromised Gate server can and cannot do: verifiers do not pin approver
  keys, so whoever holds the Gate signing key can issue an approval receipt
  that verifies (roadmap item 1.6).
- `SECURITY.md` is now a full vulnerability disclosure policy: email or GitHub
  private vulnerability reporting, scope (this repository, `perathos-gate` and
  the hosted Gate), what is out of scope, rules for testing the hosted Gate,
  safe-harbour wording for good-faith research, and response targets
  (acknowledgement within 5 working days, previously 3). No bug bounty
  payments.

## [1.3.1] - 2026-11-10

### Fixed
- `require_approval()` / `perathos gate request` print the approve link to
  stderr as soon as the request exists, instead of only after a timeout. Without
  a webhook the requester is the only one who has the link (#69).

### Added
- `perathos gate request --ttl SECONDS` (60-3600, default 600) sets how long
  the request stays approvable on the server. Ten minutes proved too short when
  the link has to be carried to a phone by hand.

### Notes
- First hosted approval at gate.perathos.com verified end to end on a real
  phone passkey (2026-11-10).

## [1.3.0] - 2026-11-06

### Added: Perathos Gate (client side)
- `docs/specs/GATE_V1.md`: protocol and receipt format for human approval of
  irreversible agent actions. The WebAuthn challenge is a hash of the exact
  request and the decision, so the approver's passkey signs *this* action;
  the Gate server also signs the receipt.
- `perathos/gate.py`: receipt construction and offline verification (ES256,
  EdDSA, RS256 passkeys; user verification required; origin, RP id, challenge
  and args binding checked), `GateClient`, `apply_gate` and the
  `require_approval()` SDK for any agent or script.
- The guard asks a person when it blocks an action and Gate is configured:
  Claude Code waits (`gate_wait`, default 120 s; installer raises the hook
  timeout to match), Cursor and the MCP proxy deny with the approval link and
  allow the retry once approved. Approvals are single-use and bound to the
  arguments; the receipt hash is recorded as `guard.approval`.
- `perathos gate login | status | request | verify`.
- Evidence packs include approval receipts; `evidence verify` checks them.

## [1.2.0] - 2026-11-05

### Added
- Remote signers (`perathos/signers.py`): `vault:<mount>/<key>` (HashiCorp
  Vault transit), `gcpkms:<key version>` (Google Cloud KMS Ed25519) and
  `command:<program>` (any HSM/YubiKey/remote signer via a two-verb
  protocol). Every remote signature is verified against the public key before
  use. `perathos signer [SPEC]` tests one; `perathos config signer SPEC`
  makes it the recorder's signer for checkpoints, evidence-pack manifests and
  the MCP proxy.
- Approver keys (`perathos/approvers.py`, `perathos approvers add|list|remove`):
  once any approver is listed, the guard accepts only preconditions signed by
  a listed key. `perathos precondition add --signer SPEC` signs with an
  approver key held off the machine. Evidence packs include `approvers.json`.
- Anchor mirror: `perathos config anchor_mirror DIR` (or
  `PERATHOS_ANCHOR_MIRROR`) appends a copy of every timestamp to a second
  folder.
- Readiness report: `perathos doctor --recorder [--network] [--json]
  [--out report.md]` with PASS/WARN/FAIL per check; exit 1 on any FAIL.
- `perathos config` for `signer` and `anchor_mirror`.

### Fixed
- Hooks are installed in exec form (absolute `perathos-hook` path + args), so
  they run whether Claude Code uses PowerShell, cmd or bash and regardless of
  PATH. Found in a live test against Claude Code 2.1.308: with the bare
  command name, a virtual-environment install was not found from PowerShell,
  which with fail-closed hooks would block every tool call.
  `PERATHOS_HOOK_COMMAND_STYLE=shell` keeps the old form.
- `command:` signer paths with quotes on Windows.

### Added
- `docs/CONTROL_MAPPING.md`: artefact-by-artefact mapping to AIUC-1 (D003.x, E015.x,
  E001, E004, E009, B006, B007, A008, E018), SOC 2 TSC, NCSC guidance, ISO/IEC 42001 Annex A,
  EU AI Act Articles 12 and 14, NIST AI RMF and FRE 902(13)/(14), with coverage and gaps
  stated per control; linked from the README and the auditor guide.
- `docs/SECURITY_ASSESSMENT.md`: a vendor security questionnaire answered from the code
  (data handled, egress, dependencies, keys, supply chain, disclosure, threat model and
  limits, red-team summary).
- The guard now also fails closed inside the hook: an exception in guard evaluation
  denies the call (rule `guard.error`) on Claude Code and Cursor, instead of allowing it.
- `docs/specs/PRECONDITION_V1.md`: standalone specification of signed safety
  preconditions for agent actions (data model, canonicalisation, signature, validity
  and scope rules, binding into receipts, security considerations), offered as input
  to IETF SCITT agent-receipt work.
- Release workflow: GitHub build provenance attestations
  (`actions/attest-build-provenance@v4`) for the sdist, wheel and SBOM; a CycloneDX
  SBOM of the wheel generated from a clean virtualenv; a GitHub Release per tag with
  those files attached. PyPI trusted publishing is unchanged. Verify with
  `gh attestation verify <file> -R perathos-protocol/perathos`.
- Site: a "Work with us" section (AIUC-1 agent-evidence readiness) linking the control
  mapping and the security assessment.
- README: "Security and procurement" section.

### Changed
- `SECURITY.md`: contact is now hello@perathos.com (the old security@perathos.io address
  is removed), response targets, 90-day coordinated disclosure, supported versions 1.x,
  scope covers the flight recorder, guard, MCP proxy and browser verifier.
- `docs/specs/RECEIPT_V1.md`: precondition scope wording matches 1.1.0 whole-token
  matching; links the new precondition spec.

## [1.1.0] - 2026-11-04

Guard hardening after an independent red-team of 1.0.0.

### Fixed
- The guard let about thirty accident-class commands through. Now blocked:
  any recursive `rm` (with or without `-f`), Windows `del /s`, `rmdir /s`,
  `rd /s`, `format`, PowerShell `rm -r`/`ri -Recurse`, `find -delete`,
  `truncate -s 0`, `dd of=`, `shred`, `mv … /dev/null`, `: > file`,
  `git reset --hard`, `git clean -fdx`, `git checkout -- .`, `git branch -D`,
  `git stash drop`, `git push --mirror`, `shutil.rmtree`, `fs.rmSync`,
  `rimraf`, and SQL with comments or newlines. Commands are normalised
  (quotes stripped, comments collapsed) before matching, so `r""m -rf` and
  `k''eys` no longer slip past.
- Scripts are scanned: `bash x.sh`, `./x.sh`, `python x.py`, `psql -f x.sql`
  have the file's content checked, and writing a script (`.sh`, `.py`, `.sql`
  …) that contains a destructive command is denied like the command itself.
- The agent can no longer switch the recorder off unnoticed: writes to
  `.claude/settings*`, `.cursor/hooks.json`, managed settings and anything
  under `.perathos/` are denied (reads are fine). Any mention of
  `signing.key` is denied.
- Precondition `--scope` now matches whole tokens, so `--scope build` no
  longer covers `postgres-build-data`.
- `session verify` and `evidence verify` print `VALID_UNCONFIRMED_SIGNER`
  when no key is pinned, instead of a bare VALID.
- The MCP proxy handles JSON-RPC batch arrays: each call is recorded and
  guarded, denied calls are answered in a batch response.
- The `[Unreleased]` MIT claim is now backed by a LICENSE file and
  `pyproject.toml` license metadata (GitHub showed "no license").

### Added
- Fail-closed hooks: `onFailure: "block"` on the Claude Code guard hook,
  `failClosed: true` on Cursor's.
- `perathos hooks install --scope managed`: writes Claude Code's managed
  policy file with `allowManagedHooksOnly: true`.
- `tests/test_guard_hardening.py`: the red-team's bypass list (41 commands),
  27 safe commands, script and write scanning, scope matching, fail-closed
  installs, unpinned-verify wording, MCP batches.

## [1.0.0] - 2026-11-04

The flight recorder is feature-complete: Claude Code, Cursor and any MCP
client; tamper-evident receipts, signed checkpoints, independent timestamps,
a destructive-command guard, evidence packs, and two independent verifiers
(CLI and browser).

### Added: any MCP client, via a recording proxy
- `perathos mcp-proxy --name X [--guard] [--anchor] [--seal-every N] -- <server cmd>`
  relays MCP stdio unchanged and records every `tools/call` as `pre`/`post`
  receipts (`mcp__<name>__<tool>`); guarded calls get an `isError` tool
  result instead of reaching the server; signed checkpoints every N calls and
  at the end. Tested with the official MCP client against a real MCP server.
- The guard now scans the string arguments of generically named MCP tools
  with the shell/SQL rules (`execute_sql` carrying `DROP TABLE` is blocked).

### Added: browser verifier and project site
- `site/verify/`: verifies an evidence pack entirely in the browser (signed
  manifest, files, receipt chain, checkpoint and precondition signatures,
  anchor/checkpoint consistency). RFC 3161 token signatures remain CLI-only,
  and the page says so. `site/` deploys to GitHub Pages.
- `perathos evidence verify` now also checks each precondition in a pack is
  unmodified and signed, matching the browser verifier.

### Changed
- Package imports are lazy (PEP 562); the public API is unchanged.
- New lean `perathos-hook record` entry point; `perathos hooks install` uses
  it and upgrades earlier `perathos hooks record` entries on `--force`.
- CI runs on Linux, Windows and macOS with Python 3.11 to 3.13.
- Docs: `docs/QUICKSTART.md`, `docs/FOR_AUDITORS.md`; README covers Cursor,
  the MCP proxy and the browser verifier; the per-hook overhead is stated as
  measured (about 0.35 s on a Windows laptop, ~20 ms of it recording).

### Added: Cursor support for the flight recorder and guard
- `perathos hooks install --agent cursor [--guard] [--anchor] [--scope project|user]`
  writes Cursor's `.cursor/hooks.json` (or `~/.cursor/hooks.json`), keeping
  unrelated hooks; `--force` replaces earlier perathos entries. The default
  `--agent claude-code` is unchanged.
- `perathos hooks record-cursor [--guard] [--anchor]` (new module
  `perathos/integrations/cursor.py`) records `beforeShellExecution`,
  `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution` and
  `afterFileEdit` as `pre`/`post` receipts, and seals the chain with a
  signed checkpoint on `stop` and `sessionEnd`. With `--guard`, destructive
  shell commands and MCP tools, and reads of the signing key
  (`beforeReadFile`), are denied in Cursor's `permission` format unless a
  signed precondition covers them; the deny holds even if recording fails.

## [0.5.0] - 2026-11-04

### Added: evidence packs and the PocketOS replay demo
- `perathos session export <id> --out DIR` writes an evidence pack (session
  log, head witness, anchors, the preconditions the guard relied on,
  `verification.json`, a one-page `REPORT.md`/`REPORT.html`, `VERIFY.md`) and
  a `MANIFEST.json` listing every file's SHA-256, signed with the local key;
  plus a `.zip`.
- `perathos evidence verify <dir|zip>` re-checks a pack from its own files:
  manifest signature, missing/added/modified files, receipt chain,
  checkpoint signatures and RFC 3161 tokens. Zip paths are checked for
  traversal.
- `examples/pocketos_replay/replay.py`: the April 2026 production-volume
  deletion replayed without and with Perathos, in a throwaway folder with a
  temporary key. Runs in CI with `--offline`.
- `python -m perathos` works as an alias for the CLI.
- README now leads with the flight recorder.

## [0.4.0] - 2026-11-04

### Added: independent timestamps and the destructive-command guard
- `perathos[anchor]` extra (rfc3161-client). `perathos session anchor`,
  `perathos hooks install --anchor` and `perathos hooks record --anchor`
  timestamp each signed checkpoint with an RFC 3161 TSA (default
  freetsa.org; root pinned in `perathos/data/tsa/`). Anchors live in
  `~/.perathos/anchors/`. `session verify --anchors/--require-anchor/--tsa-root`
  verifies tokens offline and reports `ERR_TRUNCATED` when an anchor names a
  checkpoint the log no longer has. Embedded token certificates are never
  trusted as roots (a test pins this).
- `perathos hooks install --guard` / `hooks record --guard`: PreToolUse
  denies destructive commands (about 20 rule families plus destructive MCP
  tool names) unless an unexpired precondition signed by the local key covers
  the target. Fails closed: the deny is emitted even if recording fails.
  Agents may not run `perathos precondition`/`keygen` or read the key.
- `perathos precondition add --scope X --check CMD | --manual REASON [--ttl]`
  and `precondition list`.
- Receipts gain an optional `guard` field; `session verify` reports blocked
  calls. Spec updated (anchors and preconditions).

### Changed
- Reinstalling hooks with different flags replaces the old perathos entries
  instead of adding duplicates.

### Added: flight recorder for coding agents
- `perathos hooks install --recorder` installs PreToolUse, PostToolUse, Stop
  and SessionEnd hooks running `perathos hooks record`. Every tool call is
  written to `.perathos/sessions/<session_id>.jsonl` as hash-chained receipts
  (hashes of arguments and results only, never content), and every turn is
  sealed by an Ed25519-signed checkpoint. A `.head.json` witness records the
  latest checkpoint.
- `perathos session list | show | verify`. `verify` detects edited, inserted,
  deleted and reordered receipts, stripped or forged signatures, re-signing
  by another key (with `--verify-key` / `--trust-jwks`) and truncation before
  the witnessed checkpoint. Unsigned checkpoints fail unless
  `--allow-unsigned`.
- Library: `perathos.recorder.record_hook_event`, `verify_session`.
- Receipt format spec: `docs/specs/RECEIPT_V1.md`.

### Fixed
- `perathos hooks install` wrote the Stop hook in a flat shape that Claude
  Code does not run, so the Stop hook never fired for anyone who installed it.
  It now writes the nested `{"hooks": [{"type": "command", ...}]}` shape and
  migrates old flat entries on reinstall.
- README showed `perathos hooks install claude-code`, which errors (the
  command takes no argument).

### Changed (breaking for CLI and MCP callers)
- `perathos verify` now **fails on unsigned bundles by default** (exit 1,
  `ERR_UNSIGNED`). An unsigned bundle only proves its hashes are internally
  consistent; anyone can create one, so it says nothing about who issued it.
  Pass `--allow-unsigned` for a local consistency check. `--require-signed`
  is kept as a hidden, deprecated no-op.
- The MCP tool `perathos_verify_bundle` applies the same default and takes an
  `allow_unsigned` field.
- Library: `verify_bundle(..., require_signed=True)` returns `ERR_UNSIGNED`.
  The library default is unchanged (`False`) for backward compatibility.

### Fixed
- Dependency caps: `mcp<2` (MCP SDK 2.x removed APIs the server and tests use)
  and `ruff<0.16` (0.17 added rules failing untouched files). CI had not run
  since July, so both drifts surfaced on the first new PR.
- The Claude Code Stop hook found **0 sources in real sessions**: real
  transcripts nest `tool_result` blocks inside a `user` entry's
  `message.content`, but the extractor only read top-level lines (the format
  the old tests invented). It now reads the nested format, keeps the flat one
  as a fallback, and skips non-text blocks (images, tool references). New
  tests use a fixture with the exact field structure of a real session.

### Added — Claude Code hook + MCP server
- `perathos hooks install claude-code` / `perathos hooks stop-check` — a Stop
  hook that grounds a coding agent's final turn summary against its own
  session's tool outputs (`hallucination_detector` extractive +
  `symbolic_solver`, both local/deterministic) and writes a signed Proof
  Bundle receipt to `.perathos/receipts/`. Never blocks the agent; surfaces
  findings via `additionalContext`.
- `perathos-mcp` (optional `perathos[mcp]` extra) — an MCP server exposing
  `perathos_verify_answer` and `perathos_verify_bundle` as tools for any MCP
  client. Tested end-to-end via a real in-memory MCP client/server session,
  not just direct function calls.
- `perathos/errors.py` — the CLI's error-code explanations extracted into a
  shared module so the CLI and the MCP server give byte-identical
  explanations, not two copies that can drift.

## [0.3.1] - 2026-06-23

### Added — Legal Citation Verifier M1 (coverage + reproducibility protocol)
- **Multi-reporter coverage.** The parser now recognizes the major federal /
  SCOTUS reporters (`F.2d`, `F.3d`, `F.4th`, `F. Supp.`, `F. Supp. 2d`,
  `F. Supp. 3d`, `S. Ct.`, `L. Ed.`, `L. Ed. 2d`) with their real published
  volume ranges. An out-of-range volume (e.g. `1500 F.3d`, past the series' final
  volume 999) is now caught as a fabrication even where individual cases are not
  indexed. A plausible in-range cite we do not hold stays INCONCLUSIVE — so the
  Mata v. Avianca-class fake (`925 F.3d 1339`) is honestly reported as
  unverifiable, not falsely flagged. Year parentheticals with a court
  (`(11th Cir. 2019)`) parse correctly.
- **Complete-coverage existence mechanism.** A snapshot may declare
  `complete_volumes` per reporter; within a complete range a non-resolving cite
  becomes a fabrication (if it were real we would hold it). Shipped empty (this is
  a curated, not exhaustive, snapshot) — the mechanism is the on-ramp for the
  data investment that turns INCONCLUSIVE into FAIL for nonexistent-but-plausible
  cites.
- **End-to-end signed bundle binding.** `perathos cite-check --sign --out
  brief.bundle.json` emits a Proof Bundle whose `integrity_hash` binds the
  citation verdict AND the `corpus_hash`, re-verifiable offline
  (`perathos verify --file ...`) by a counterparty; tampering with a bound verdict
  breaks verification. This makes the cross-party, tamper-evident citation record
  concrete.
- Snapshot updated to `us-caselaw-v1.1-2026.06`; `RULES_VERSION` -> 1.1.0.

## [0.3.0] - 2026-06-23

### Added — Legal Citation Verifier (engine 128), M0
The first **domain** verifier and the chosen wedge into the regulated-AI buyer:
deterministically check that the U.S. legal citations in an AI output exist and
are attributed to the right case. Real, named pain (lawyers sanctioned for
AI-fabricated citations).
- New `perathos.legal` subpackage: a regex citation parser, a pinned
  **content-addressed** public case-law snapshot (`CitationCorpus`, M0 = curated
  landmark SCOTUS), and `CitationVerifier` (engine 128).
- **No network at verify time** — resolution is a pure function of (output,
  snapshot); the `corpus_hash` + `engine_rules_version` are bound into the
  VerdictRecord evidence, so a verdict is reproducible offline by a counterparty.
- **Honesty-first verdicts:** impossible-volume and name↔cite misattribution →
  FAIL; a cite outside the snapshot → INCONCLUSIVE (never a false fabrication
  flag); no cites → NOT_APPLICABLE. Cardinal rule upheld: zero false positives on
  real, in-coverage citations (enforced by a red-team test).
- New CLI: `perathos cite-check brief.txt` (exits non-zero on a fabrication).
- `perathos[legal]` extra (pure stdlib today). See docs/specs/CITATION_VERIFIER.md.

## [0.2.7] - 2026-06-23

### Security / hardened (trust anchor — TrustStore.from_jwks)
A probe of the trust layer confirmed the verify-time gate is **sound** — an
untrusted signer and a JWKS kid-spoof (claiming a trusted kid while embedding an
attacker key) are both rejected, because verification re-derives the kid from the
actual key bytes and byte-compares. `from_jwks` is now hardened to match:
- **Validates every JWKS entry** instead of crashing on malformed input — a
  non-object JWKS, non-list `keys`, non-object entries, missing/non-string
  `kid`/`x`, invalid base64url, or a non-32-byte key now raise a clear
  `ValueError` (previously `KeyError`/`TypeError`/`binascii.Error`).
- **Strict base64url** (`validate=True`) — a garbage `x` like `"@@@@"` is rejected
  instead of silently decoding to an empty key.
- **kid must match `kid_for(x)`** — a tampered/kid-spoofed entry is rejected at
  load time rather than stored as an inert entry, surfacing a bad JWKS early.

## [0.2.6] - 2026-06-23

### Fixed (crypto-core hardening — verify_bundle must never raise)
An adversarial probe pass against the verification path found 5 hostile bundles
that made `verify_bundle()` **raise** instead of returning its documented
`(valid, error_code)` — a contract break and, for a verification gateway taking
attacker-controlled bundles, a denial-of-service.
- **Non-string `answer`** (`{"answer": 1234}`) crashed the `.encode()` cross-check
  (AttributeError) — now type-checked → `ERR_MALFORMED_BUNDLE`.
- **Non-dict `verification`** (a forged, self-consistent bundle with
  `verification: "…"`) crashed the `.get()` verdict cross-check (AttributeError)
  — now rejected early → `ERR_MALFORMED_BUNDLE`.
- **Deeply-nested `_trace` / `verification`** crafted to exhaust the stack during
  canonicalization raised RecursionError (a DoS) — now caught → `ERR_MALFORMED_BUNDLE`.
The signature path (`verify_signature`) was probed too and already handled
non-dict signatures, bad hex, algorithm-confusion, and missing fields cleanly.

## [0.2.5] - 2026-06-23

### Fixed
- **SymbolicSolver no longer over-skips a result followed by a sentence comma.**
  The 0.2.4 ambiguous-comma guard was too eager: a trailing punctuation comma
  (`"17 * 23 = 391, confirmed"`) was treated as a decimal/grouping comma and the
  correct claim was skipped. The guard now only fires on a comma *between digits*
  (`\d,(?=\d)`), so trailing punctuation is ignored while `3,5` is still skipped.
  (Caught by the training-ops cross-repo engine tests against 0.2.4.)

## [0.2.4] - 2026-06-23

### Fixed (adversarial hardening — format / encoding / evasion / injection)
An adversarial probe pass against the engines surfaced 9 real weaknesses; all are
fixed here, with the cardinal rule upheld: an engine must **fail closed** to
NOT_APPLICABLE/INCONCLUSIVE on ambiguity, never false-FAIL a correct answer.
- **SymbolicSolver no longer false-flags ambiguous numerals.** Scientific
  notation (`2e3 = 2000`), caret powers (`10^3 = 1000`), and decimal commas
  (`3,5 * 2 = 7`) were being parsed as fragments (`"3 = 2000"`) and reported as
  wrong. The engine now skips a match glued to a letter/`.`/`^` or carrying an
  ambiguous comma (not a clean thousands group) instead of misreading it.
  Legitimate thousands separators and `x`-multiplication still verify.
- **HallucinationDetector checks non-`$` currencies** (`€`, `£`, `¥`) — a
  fabricated `€900` is now caught instead of being silently uncheckable.
- **SchemaValidator rejects non-finite numbers** — the json stdlib's `NaN` /
  `Infinity` / `-Infinity` extension is refused (it is not valid JSON and must
  not satisfy a `{"type": "number"}` schema).
- **TemporalConsistency is morphology-tolerant** — plurals (`smartwatches`,
  `cars`) and hyphen variants (`smart-watch`) no longer evade the anachronism
  check, while staying word-safe (`cares`/`cards` still don't match `car`).

### Documented (scope limit, by design)
- Extractive grounding checks a specific's PRESENCE, not its polarity, so a
  negated claim whose value still appears in the source (`"NOT within 30 days"`)
  is not caught extractively. This is the entailment layer's job — pass an
  `entailment_fn` (or use the ClaimEntailment verifier) to catch contradictions.

## [0.2.3] - 2026-06-23

### Changed
- **TemporalConsistency timeline expanded (~50 modern terms)** — the checker
  could only flag anachronisms for terms in its curated dict, so an off-timeline
  term like `"smartwatch in 1850"` was silently skipped (counted as a miss).
  Added unambiguous, conservatively-dated 20th/21st-century terms (smartwatch,
  bluetooth, wi-fi, usb, qr code, blog, podcast, crispr, blockchain, chatgpt, …);
  homographs (tablet/drone/stream) are deliberately omitted so word-boundary
  matching can't false-fire on everyday words. Per-call `ctx.timeline` still
  extends/overrides for domain terms, so coverage isn't a fixed dict. Closes
  engine gap #3 from training-ops `docs/ENGINE_GAPS.md` — the last documented gap.

## [0.2.2] - 2026-06-23

### Fixed
- **HallucinationDetector now matches specifics like-with-like** — it previously
  flattened all sources into one digit-soup and checked bare digits, so a
  fabricated duration `"90 days"` was wrongly grounded by an unrelated `"$90"`
  elsewhere in the source (a substring collision). Each specific (money, %, year,
  duration) is now extracted per kind from the sources and a claim is grounded
  only by a token of its OWN kind, with numeric values compared (so `$1000` still
  matches `$1,000.00`) and durations matched on (number, unit-family). Closes
  engine gap #2 from training-ops `docs/ENGINE_GAPS.md`.

## [0.2.1] - 2026-06-23

### Fixed
- **SymbolicSolver now handles modulo (`%`)** — the equation regex omitted `%`,
  so `"17 % 5 = 2"` misparsed as `"5 = 2"` and false-positived a correct answer.
  Added `%` to the char class (the evaluator already supported `ast.Mod`); a bare
  percentage like `"3.2%"` can't form a binary expression, so it is skipped, not
  flagged. Closes engine gap #1 from training-ops `docs/ENGINE_GAPS.md`.

### Changed
- **Crypto backend unified on `cryptography` (pyca)** instead of PyNaCl
  (open-core consolidation, decision #1). Ed25519 signing/verification in
  `signing.py` and `keytrust.py` now use the industry-standard `cryptography`
  library — the same backend as the gateway — so signers are shareable across
  the VRL stack. Signature format and behavior are unchanged (Ed25519 is
  interoperable); existing signed bundles still verify. Core deps: `click` +
  `cryptography` (was `pynacl`); `doctor` now reports `cryptography`.

### Added
- **Proof Bundle v2** (open-core consolidation, stage 3 — the unified format).
  v2 keeps perathos's hash-chain integrity and adds: a `computed` flag on each
  verdict (only engine-computed verdicts count as independently verified), a
  top-level `verdict` + `model` (bound/cross-checked), and an optional
  `answer` (hash-only by default; bound to output_hash). `create_bundle` emits
  v2 by default; `verify_bundle` **dual-reads** by `bundle_version`, so every
  existing v1 bundle still verifies. New checks: `ERR_VERDICT_MISMATCH`,
  `ERR_ANSWER_MISMATCH`. `prove` gained `--model`, `--include-answer`,
  `--schema`, and now runs the full engine suite (Symbolic/Hallucination/
  Schema/Temporal + Cross-Examiner + Claim-Entailment) when verifying.
- **Real verifier engines** (`perathos.engines`), the canonical core's
  deterministic, model-free engines (open-core consolidation, stage 2 — ported
  from the gateway): `SymbolicSolver` (123, recompute arithmetic),
  `HallucinationDetector` (125, extractive grounding vs sources + optional
  entailment hook), `SchemaValidator` (126, jsonschema with remote-$ref refused),
  `TemporalConsistency` (127, anachronism detection). With CrossExaminer (122)
  and ClaimEntailment (124) that is 6 of the 7 named verifiers. Each runs behind
  the INCONCLUSIVE-safe wrapper and binds a reproducible evidence digest.
  `VerificationContext` gained `sources`, `schema`, `timeline`. SchemaValidator
  needs the `schema` extra.
- **Key management & trust anchoring** (`perathos.keytrust`), the canonical VRL
  key layer (open-core consolidation, stage 1): a pluggable `Signer` —
  `LocalSigner` and `KmsSigner` (private key never leaves a KMS/HSM via an
  injected sign function) — plus a `TrustStore` of trusted keys by derived `kid`,
  exportable/importable as JWKS. `sign_bundle()` now accepts a `Signer`;
  `verify_bundle(..., trust_store=...)` and `verify --trust-jwks <file>` reject
  any signer not in the trusted set (`ERR_UNTRUSTED_SIGNER`). Signature format is
  unchanged, so existing bundles still verify; KMS-signed bundles are
  shape-identical to locally-signed ones.

## [0.2.0] - 2026-06-16

### Added
- **Multi-verifier pipeline** bound into the signed proof bundle: verdict
  records + aggregate verdict are folded into `integrity_hash` (tamper-evident).
  Reference verifiers: Cross-Examiner (122, self-consistency) and
  Claim-Entailment (124, claim decomposition + entailment).
- **Real NLI entailment backend** (`perathos.verifiers_nli`, optional `[nli]`
  extra) that plugs into Claim-Entailment via the `entailment_fn` hook; verified
  to label supported/contradicted against evidence with a real transformers
  cross-encoder. Core `import perathos` remains torch-free.
- **Confidence calibration** (`perathos.calibration`): temperature scaling,
  reliability binning, and Expected Calibration Error — so `confidence_bps` is
  fit and measured, not assumed.
- **Evidence binding**: each verdict records SHA-256 digests of the exact
  samples/documents it judged (reproducible verification).
- **Signer pinning**: `verify_bundle(..., expected_verify_key=...)` and
  `verify --verify-key` reject signer substitution (`ERR_UNEXPECTED_SIGNER`).
- Enterprise docs: `docs/THREAT_MODEL.md`, `SECURITY.md`,
  `docs/ENTERPRISE_FAQ.md`, and a cited training-data dossier
  (`docs/research/TRAINING_DATA.md`).
- CLI verification: `prove --evidence/--evidence-text/--sample/--sample-text/--nli/--mode`
  runs the pipeline and binds verdicts; `perathos doctor` diagnostic.
- `verify` policy gates: `--require-signed` and `--require-pass` enforce a
  deployment policy (signed + pinned + PASS) in one call.
- Runnable harness in `scripts/`: `calibrate.py` (fit + ECE) and
  `train_entailment.py` (fine-tune the NLI model); `train` extra.
- Secure release workflow (`.github/workflows/release.yml`) with a clean-install
  smoke gate and PyPI trusted publishing (OIDC, no API token).

### Fixed (security / correctness)
- `verify()` now validates the Ed25519 signature when present — a forged
  signature on an intact chain previously passed.
- Signature with a non-`ed25519` algorithm is rejected (`ERR_UNSUPPORTED_ALGORITHM`).
- Canonical serialization rejects NaN/Infinity and non-string keys; strict
  lowercase hex for signatures (no serialization malleability).
- `verify_bundle` returns `ERR_MALFORMED_BUNDLE` instead of crashing on hostile
  input; `inspect` is fully type-guarded and markup-safe.
- Atomic writes (tempfile + fsync + `os.replace`) for bundles and keys;
  owner-only key ACL on Windows; `list_bundles` tolerates concurrent deletion.
- `perathos prove` crash, keygen cp1252 crash, and other earlier fixes.

### Changed
- `verify_output(output_text, input_text='', *, verifiers=..., context=...)` —
  argument order now matches `create_bundle`/`prove`.
- CI parity in the agent harness (ruff gate before pytest); resilient git-push
  handling; globbed source context; workflow concurrency groups; version-bounded
  agent deps.

### Quality
- Test suite expanded to 183 (adversarial tamper, malformed-bundle robustness,
  aggregation, calibration, NLI decision, gated real-model integration).
- Hardened against an internal 37-agent audit (18 findings fixed; cryptographic
  core found sound — no critical/high).
