# Reviewing a Perathos evidence pack

For auditors, insurers, incident reviewers and anyone handed an evidence pack about an AI coding
agent's session. You do not need to trust the person who sent it, or this project's report:
everything can be re-checked from the files.

## Check it

1. Get the signer's **public key** from the operator through a channel other than the pack itself
   (email signature, ticket, call). A pack signed by a key you have not confirmed proves only that
   *someone* sealed it.
2. Run either:
   - `pip install 'perathos[anchor]'` then
     `perathos evidence verify evidence-pack.zip --verify-key <key>` (checks everything, including
     the RFC 3161 timestamp signatures), or
   - drop the zip into https://perathos-protocol.github.io/perathos/verify/ (runs in your browser, uploads nothing; timestamp signatures
     still need the CLI).
3. Read `REPORT.html` (one page) for the summary, and `verification.json` for the details.

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

## Questions worth asking the operator

- Was the key that signed this pack held where the agent could not read it?
- Is a copy of the anchors file (`~/.perathos/anchors/<session>.jsonl`) kept somewhere the agent and
  the machine's users cannot change? If so, check the pack against that copy with
  `perathos session verify <log> --anchors <copy>`.
- Which hooks were installed (`.claude/settings.json`, `.cursor/hooks.json`, MCP client config),
  and was `--guard` on?
- Can you provide the original arguments or output for receipt *N*? Hash them and compare with the
  receipt's `args_hash` / `result_hash`.

## Formats

Receipts, anchors and preconditions: [specs/RECEIPT_V1.md](specs/RECEIPT_V1.md). Evidence pack
layout: `perathos/evidence.py`. Everything is JSON, SHA-256, Ed25519 and RFC 3161, so it can be
re-implemented independently; the browser verifier (`site/verify/core.js`) is a second
implementation of the same checks.
