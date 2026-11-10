# Reviewing a Perathos evidence pack

For auditors, insurers, incident reviewers and anyone handed an evidence pack about an AI coding
agent's session. You do not need to trust the person who sent it, or this project's report:
everything can be re-checked from the files.

## Check it

0. A pack verified without a pinned key shows `VALID_UNCONFIRMED_SIGNER`: the record is
   internally consistent, but anyone with a key can produce such a record. Always pin.
1. Get the signer's **public key** from the operator through a channel other than the pack itself
   (email signature, ticket, call). A pack signed by a key you have not confirmed proves only that
   *someone* sealed it.
2. Run either:
   - `pip install 'perathos[anchor]'` then
     `perathos evidence verify evidence-pack.zip --verify-key <key>` (checks everything, including
     the RFC 3161 timestamp signatures), or
   - drop the zip into https://perathos-protocol.github.io/perathos/verify/ (runs in your browser, uploads nothing; timestamp signatures
     still need the CLI, and the browser verifier **does not check Gate approval receipts at
     all**: see step 3).
3. If the pack has an `approvals/` folder, a person approved at least one destructive action
   through Perathos Gate with a passkey. Use the CLI, and get two more values from the operator
   through a separate channel: the **Gate server's public key** and the **public key of each
   approver's passkey** (`perathos gate approvers --keys` prints them on the operator's machine).
   Then run
   `perathos evidence verify evidence-pack.zip --verify-key <key> --gate-key <gate key> --approver-key <passkey key>`
   (`--approver-key` can be repeated). The `approvals` line of the output states what was
   checked, for example `approvals  2 cited, 2 verified, Gate key UNCONFIRMED, approvers NOT PINNED`:
   - `Gate key UNCONFIRMED` (first word `VALID_UNCONFIRMED_GATE`): the receipts are internally
     consistent, but anyone can run a Gate and sign such receipts. Pass `--gate-key`.
   - `approvers NOT PINNED`: the approver's public key was read from the receipt itself, so the
     receipt shows that the Gate server vouched for that passkey, not that it belongs to a
     person you know. Whoever holds the Gate's signing key could name a passkey of their own.
     Pass `--approver-key`.
   If your own machine has a Gate key or approvers pinned (`perathos gate login`,
   `perathos gate trust`), those are used when you pass nothing; the line says so
   (`local pin`).
   To check a single approval receipt you were sent on its own, run
   `perathos gate verify receipt.json --gate-key <gate key> --approver-key <passkey key>`
   (`--approver-key` can be repeated or comma-separated, as `perathos gate approvers --keys`
   prints it). It replaces any approvers pinned on your machine or in `PERATHOS_GATE_APPROVERS`,
   prints `approver pinned (--approver-key)` when the receipt's approver is one of them, and
   `INVALID ERR_GATE_UNTRUSTED_APPROVER` (exit 1) when it is not. A receipt checked on its own
   shows who approved which request; it does not show which run or arguments the approval was
   then used for. Only `evidence verify` on a full pack checks that.
4. Read `REPORT.html` (one page) for the summary, and `verification.json` for the details.

## What a VALID pack establishes

- **Integrity:** no receipt up to the last checkpoint was edited, removed, inserted or reordered
  after it was written, and no file in the pack was changed after export (signed manifest).
- **Who sealed it:** each checkpoint was signed by the key you confirmed.
- **When (if anchored):** each anchored checkpoint existed no later than the time asserted by an
  independent RFC 3161 authority. An anchor for a checkpoint missing from the log proves the log
  was cut (`ERR_TRUNCATED`).
- **Safeguards:** every destructive call the guard matched is recorded as blocked or allowed. An
  allowed call names the signed precondition it relied on: the check that was run (for example
  a backup restore listing), who signed it, when, and its expiry.
- **Approvals by a person (if any, CLI only):** every call the log records as approved through
  the Gate points at a receipt that is in the pack, is an approve decision, and was given for
  the same arguments hash as that call (`ERR_APPROVAL_MISSING`, `ERR_APPROVAL_NOT_APPROVED`,
  `ERR_APPROVAL_ARGS_MISMATCH` otherwise). Each receipt's Gate signature and passkey signature
  verify. That the Gate and the approver are the ones you expect is established only for the
  keys you supplied (step 3).

## What it does not establish

- **Which model ran.** The `model` field is self-reported by the agent tool.
- **Completeness of recording.** If hooks were switched off for part of the work, that gap is not
  visible. Ask how recording was enforced (for example a managed settings file).
- **Content.** Tool arguments and outputs are stored only as SHA-256 hashes. The operator can show
  an original matches; you can request specific items.
- **Truth of a precondition's check.** A precondition proves the named check ran and exited 0. Whether
  that check meaningfully tests the backup is a judgement for you.
- **Protection from a hostile agent.** The guard matches command patterns and the signing key lives
  on the operator's machine. It prevents accidents; it is not a sandbox.
- **Times of unanchored events.** Without anchors, times come from the operator's clock.
- **That an approver understood what they approved,** or that an approval was used only once
  (a repeat citation of one approval is reported as a warning), or that it was used inside its
  10-minute validity window: `evidence verify` does not compare the approval's time with the
  call's local-clock time.
- **Recording failures.** A hook that failed leaves no receipt. The operator's machine keeps a
  local count (`perathos doctor --recorder`, `~/.perathos/errors.log`); it is not in the pack
  and is not signed. A checkpoint the signer failed to sign is in the pack: it is unsigned,
  marked `signer_error`, and fails verification with `ERR_UNSIGNED`.

## Questions worth asking the operator

- Did they run `perathos doctor --recorder --out readiness.md`? The report lists, check by check,
  how the machine was set up (signer location, approvers, fail-closed hooks, managed lock,
  timestamp mirror) and whether recent logs verify. Ask for it alongside the pack.
- Who are the approvers? An `approvers.json` in the pack names them. If it is missing, the
  recorder key approved destructive actions, and anyone holding that key could have done so.

- Was the key that signed this pack held where the agent could not read it?
- Is a copy of the anchors file (`~/.perathos/anchors/<session>.jsonl`) kept somewhere the agent and
  the machine's users cannot change? If so, check the pack against that copy with
  `perathos session verify <log> --anchors <copy>`.
- Which hooks were installed (`.claude/settings.json`, `.cursor/hooks.json`, MCP client config),
  was `--guard` on, and were the hooks installed in the managed policy file (which the agent
  cannot edit) rather than the project file?
- Can you provide the original arguments or output for receipt *N*? Hash them and compare with the
  receipt's `args_hash` / `result_hash`.

## Which controls this is evidence for

[CONTROL_MAPPING.md](CONTROL_MAPPING.md) lists, control by control, what a pack supports in AIUC-1
(notably D003.4 human-approval workflows and E015.4 log integrity protection), SOC 2, NCSC guidance,
ISO/IEC 42001, the EU AI Act and NIST AI RMF, and what it does not.

## The full threat model

[THREAT_MODEL.md](THREAT_MODEL.md) sets out, component by component, what is protected and what is
not. Section 5.6 lists what `evidence verify` does not check for you: precondition signers against
the approver list, and, unless you supply or have pinned them, the Gate key and approver passkeys
on approval receipts. To report a flaw, see
[SECURITY.md](../SECURITY.md).

## Formats

Receipts, anchors and preconditions: [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md). Evidence pack
layout: `perathos/evidence.py`. Everything is JSON, SHA-256, Ed25519 and RFC 3161, so it can be
re-implemented independently; the browser verifier (`site/verify/core.js`) is a second
implementation of the manifest, receipt-chain, checkpoint-signature, head-witness and
precondition checks. It does not verify RFC 3161 token signatures or Gate approval receipts
([specs/GATE_V1.md](specs/GATE_V1.md)); the CLI does.
