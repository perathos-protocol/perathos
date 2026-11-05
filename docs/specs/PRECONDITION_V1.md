# Signed safety preconditions for agent actions, v1 (`perathos.precondition/v1`)

Status: draft specification. Reference implementation: `perathos/guard.py`
(`create_precondition`, `check_precondition`, `find_precondition`, `decide`).
This document is written to be implementable without reading that code.

Prior art and attribution: first published in perathos 0.4.0, 2026-11-04
(<https://github.com/perathos-protocol/perathos>, MIT licence).

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY
and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals.

## 1. Concept

An AI agent that can run commands can also destroy things: a database, a
storage volume, the backups that would recover them. Asking a person to click
"approve" on each such command records only that someone clicked. A *safety
precondition* records something stronger: that a named safeguard was
**demonstrated to hold** just before the action.

1. A person, outside the agent's session, runs a named **check** that proves
   a safeguard holds, for example that the latest backup of `prod-db`
   restores (`pg_restore --list backups/prod-db.dump`).
2. Only if the check exits with status 0 is a **precondition** created: a
   signed, expiring record of which check ran, a hash of what it printed,
   which target it covers (its **scope**), who signed it and until when it is
   valid.
3. When the agent attempts a destructive action, an **enforcement point**
   (for example an agent hook) allows it only if a valid precondition covers
   the action's target. Otherwise the action is denied and does not run.
4. The decision, allow or deny, and the hash of the precondition relied on,
   are **bound into the tamper-evident record** of that action, so an auditor
   can later check that every destructive action ran under a demonstrated
   safeguard, and re-verify the precondition itself.

The agent can never authorise itself: preconditions are signed with a key the
agent must not hold, and the enforcement point denies agent attempts to create
preconditions or reach the key.

## 2. Terminology

* **Action**: a single tool call by an agent (a shell command, a file write,
  an MCP tool call).
* **Destructive action**: an action that an enforcement point's policy
  classifies as able to destroy data or the means to recover it. The policy
  (rule set) is out of scope of this document; the reference implementation's
  rules are in `perathos/guard.py`.
* **Subject**: the text an enforcement point matches scopes against, derived
  from the action (section 6.2).
* **Signer**: the holder of the Ed25519 private key that signs preconditions.
* **Trusted key**: the Ed25519 public key (or keys) the enforcement point
  accepts preconditions from.
* **Check**: a command whose zero exit status demonstrates the safeguard.

## 3. Data model

A precondition is a JSON object with exactly these members:

| Member | Type | Meaning |
|---|---|---|
| `v` | string | MUST be `"perathos.precondition/v1"`. |
| `id` | string | A unique identifier. The reference implementation uses a random UUID (version 4) in its canonical lowercase hyphenated form. |
| `kind` | string | MUST be `"safety-check"` in v1. |
| `scope` | string | The target this precondition covers (section 6.2), or `"*"` for every target. MUST NOT be empty or only whitespace. |
| `check` | string or null | The check command exactly as run. Null when `manual_reason` is used. |
| `check_exit_code` | integer or null | The check's exit status. MUST be `0` when `check` is a string (a precondition is never created for a failing check); null when `check` is null. |
| `check_output_hash` | string or null | Lowercase hex SHA-256 of the check's combined standard output followed by standard error (section 4.2). Null when `check` is null. |
| `manual_reason` | string or null | When no check command can demonstrate the safeguard: the signer's own attestation and reason. Null when `check` is a string. |
| `created` | string | Creation time, UTC, ISO 8601 / RFC 3339 with seconds precision and a `Z` suffix, e.g. `"2026-11-04T09:30:00Z"`. |
| `expires` | string | Expiry time, same format. MUST be later than `created`. |
| `signer` | string | Lowercase hex of the signer's 32-byte Ed25519 public key. |
| `precondition_hash` | string | Lowercase hex SHA-256 (section 4). |
| `signature` | object | `{"algorithm": "ed25519", "verify_key": <hex public key>, "signature": <hex 64-byte signature>}` (section 5). |

Exactly one of `check` and `manual_reason` MUST be a string; the other MUST
be null. All members MUST be present, including those that are null.

A precondition made with `manual_reason` attests only to the signer's word,
not to a demonstrated check. Enforcement points MAY refuse manual
preconditions, and auditors SHOULD report them separately.

### 3.1 Example

```json
{
  "check": "pg_restore --list backups/prod-db.dump",
  "check_exit_code": 0,
  "check_output_hash": "5f1c...e9a2",
  "created": "2026-11-04T09:30:00Z",
  "expires": "2026-11-04T10:00:00Z",
  "id": "0b8f3c1e-6c2d-4c39-9d0a-7f2a8e9b4d11",
  "kind": "safety-check",
  "manual_reason": null,
  "precondition_hash": "a3d4...7c01",
  "scope": "prod-db",
  "signature": {
    "algorithm": "ed25519",
    "signature": "9e0b...c40f",
    "verify_key": "7d2a...18be"
  },
  "signer": "7d2a...18be",
  "v": "perathos.precondition/v1"
}
```

(Hex values shortened for readability.)

### 3.2 Storage

This specification does not mandate a storage location. The reference
implementation writes each precondition as `<id>.json` in
`<project>/.perathos/preconditions/`; that file is pretty-printed JSON, which
is fine because hashing is over the canonical form (section 4.1), not the file
bytes.

## 4. Canonicalisation and hashing

### 4.1 Canonical JSON

The canonical form of a JSON object is its serialisation with:

* object members sorted by key, comparing keys by Unicode code point;
* no insignificant whitespace (separators `,` and `:` exactly);
* UTF-8 encoding, with non-ASCII characters written directly, not escaped;
* string escaping as produced by a standard JSON encoder for the remaining
  characters (`"`, `\` and control characters);
* integers written in plain decimal; NaN and Infinity forbidden;
* object keys MUST be strings.

For the members defined in section 3 (strings, integers and null), this
coincides with the JSON Canonicalization Scheme (RFC 8785). Implementations
MAY use an RFC 8785 library. Free-text members (`check`, `manual_reason`,
`scope`) can contain any Unicode text; an implementation that does not use
RFC 8785 MUST still produce identical bytes for them, and test vectors SHOULD
include non-ASCII text and control characters.

### 4.2 Check output hash

`check_output_hash` is computed as follows: concatenate the check's
standard output bytes and then its standard error bytes; decode the result as
UTF-8, replacing invalid sequences with U+FFFD; take SHA-256 of the UTF-8
encoding of that text. The output itself is not stored; whoever retains it
can show it matches.

### 4.3 Precondition hash

`precondition_hash` = lowercase hex of SHA-256 over the canonical JSON
(section 4.1) of the precondition object **without** the `precondition_hash`
and `signature` members. Every other member, including `signer`, `scope` and
`expires`, is therefore bound into the hash.

## 5. Signature

The signature is Ed25519 (RFC 8032, pure Ed25519) over the **32 raw bytes** of
the precondition hash (the decoded hex, not the hex text).

* `signature.algorithm` MUST be `"ed25519"`. Verifiers MUST reject any other
  value rather than attempt another algorithm.
* `signature.verify_key` MUST equal `signer`.
* `signature.signature` is the lowercase hex of the 64-byte signature.

## 6. Validity

### 6.1 Validity of a precondition

At time *now*, against a set of trusted keys *T*, a precondition is **valid**
if and only if all of the following hold. A verifier MUST check all of them:

1. **Version.** `v` equals `"perathos.precondition/v1"`.
2. **Unmodified.** The precondition hash recomputed per section 4.3 equals
   `precondition_hash`. A precondition that cannot be canonicalised is
   invalid.
3. **Signed.** `signature` is an object and the Ed25519 signature verifies
   over the raw bytes of `precondition_hash` under `signature.verify_key`,
   with `algorithm` equal to `"ed25519"`.
4. **Trusted signer.** `signature.verify_key` is in *T* and `signer` equals
   `signature.verify_key`. *T* MUST be configured out of band (for example the
   operator's own public key, or a pinned key set); a key taken from the
   precondition itself MUST NOT be treated as trusted.
5. **Unexpired.** `expires` parses as a timestamp and *now* is strictly before
   it. A precondition is invalid at the instant of expiry.

Verifiers SHOULD additionally check that `kind` is `"safety-check"`, that
exactly one of `check` and `manual_reason` is a string, and that
`check_exit_code` is `0` when `check` is a string. (The reference
implementation enforces these at creation; its verifier relies on the
signature, since a precondition violating them could only have been signed by
a trusted key holder.)

### 6.2 Scope match

A precondition **covers** an action when its `scope` matches the action's
subject:

* `scope` equal to `"*"` covers every subject.
* Otherwise the scope MUST occur in the subject as a **whole token**,
  compared case-insensitively: the occurrence MUST NOT be immediately preceded
  or followed by a letter, digit, `_`, `.` or `-`. So scope `build` covers
  `docker volume rm build` but not `postgres-build-data`, and scope `prod-db`
  covers `dropdb prod-db` but not `dropdb prod-db2`.

The subject is the enforcement point's text form of the action. In the
reference implementation it is the command line as the agent submitted it
for shell tools, and the tool name followed by a JSON rendering of its
arguments for MCP tools. Implementations MUST document their subject
derivation, because it determines what a scope covers.

Scopes SHOULD name the specific resource being destroyed (a database, volume,
bucket or branch name), not a verb or a generic word. `"*"` SHOULD be used only
for short-lived, deliberate maintenance windows.

### 6.3 Choosing among several preconditions

If several valid preconditions cover an action, the enforcement point MAY
choose any one. The reference implementation chooses the one with the latest
`created`. The choice MUST be recorded (section 7).

## 7. Enforcement and binding into the action record

For every action its policy classifies as destructive, an enforcement point:

1. MUST deny the action if it is an attempt by the agent to create a
   precondition, obtain or replace the signing key, or alter the
   configuration that keeps the enforcement point and recorder running,
   regardless of any precondition (**self-authorisation rule**).
2. MUST deny the action if no trusted key is configured.
3. MUST allow the action only if at least one valid (section 6.1)
   precondition covers it (section 6.2) at the time of the decision, and
   otherwise MUST deny it.
4. SHOULD tell the agent, on deny, what a person must do (which check to run
   and for which scope), without itself creating anything.
5. MUST record the decision in the tamper-evident action record **before**
   the action runs, as a `guard` member of the action's record:

   ```json
   "guard": {"decision": "allow", "rule": "sql.drop", "precondition": "<precondition_hash>"}
   ```

   * `decision`: `"allow"` or `"deny"`.
   * `rule`: identifier of the policy rule that classified the action as
     destructive (the reference implementation prefixes `script:` when the
     match was inside a script file the command runs, and `write:` when a
     script being written contains it).
   * `precondition`: on allow, the `precondition_hash` relied on; on deny,
     null.

   Because the `guard` member is inside the record's hash (in Perathos, the
   `pre` receipt of [RECEIPT_V1.md](RECEIPT_V1.md)), the decision and the
   exact precondition cannot later be altered without detection. A denied
   action never ran, so no result record follows it.

6. SHOULD emit the deny even when recording fails (fail closed), and SHOULD
   be installed so that a missing or failing enforcement point blocks the
   action rather than allowing it.

An auditor verifying a session SHOULD, for every `allow`, obtain the
precondition whose hash is recorded, verify it per section 6.1 with the time
of the action as *now*, and check that its scope covers the action. Evidence
packages SHOULD therefore include every precondition referenced by an allow
decision; Perathos evidence packs do (`preconditions/`).

## 8. Security considerations

**Agent self-authorisation.** The whole value of a precondition is that the
agent did not make it. The signing key MUST NOT be readable by the agent.
Enforcement points MUST apply the self-authorisation rule (section 7, step 1).
Pattern-based enforcement cannot see every route to a key file on the same
machine; deployments that face a hostile rather than merely mistaken agent
SHOULD keep the key in a separate account, device, KMS or HSM, and SHOULD run
the check from a context the agent cannot influence.

**Key custody.** Anyone holding the private key can mint preconditions. The
trusted key set MUST be pinned out of band. Rotation is by changing the
trusted set; preconditions signed by a removed key become invalid at once.

**Meaningfulness of the check.** A precondition proves that a named command
ran and exited 0, not that the command is a good test of the safeguard.
`pg_restore --list` proves a dump is readable, not that it is recent or
complete. Organisations SHOULD maintain an approved list of checks per
resource class and review the `check` member of preconditions in audits. The
`check` text is stored in cleartext and MUST NOT contain secrets.

**Replay within the validity window.** A v1 precondition is not consumed by
use: it covers any number of matching actions until it expires, and is not
bound to a session, machine or project. Short lifetimes (the reference
default is 30 minutes, with a maximum of 24 hours in its CLI) and narrow
scopes limit this. A future version may add single-use or session-bound
preconditions.

**Clock.** `created` and `expires` come from the signer's clock and expiry is
judged against the enforcement point's clock. A wrong clock on either side
widens or narrows the window. Enforcement points SHOULD use a synchronised
clock; where independent time matters, anchor the action record with an
RFC 3161 timestamp (as Perathos checkpoints can be) so an auditor can compare
the action's time with the precondition's window.

**Scope matching.** Token matching on a text subject can be defeated by
obfuscating the target name, just as the destructive-action policy can be
defeated by obfuscating the command. Preconditions bound the damage of
*accidents*; they do not make a pattern-based enforcement point a sandbox.

**Privacy.** Only a hash of the check's output is stored. Short or
predictable outputs can be confirmed by hashing guesses.

## 9. Relationship to control frameworks

Per [CONTROL_MAPPING.md](../CONTROL_MAPPING.md):

* **AIUC-1 D003.4** (Config: Human-approval workflows; Mandatory Control
  since 15 October 2026) asks for approval workflows for sensitive tool
  operations, including deleting or irreversibly modifying records.
  Preconditions plus the bound `guard` decisions are evidence for this control
  for destructive data operations: the enforcement point denies them until a
  person has run and signed a precondition, and every allow records which one.
  Financial transactions and credential changes are not covered by the
  reference rule set.
* **AIUC-1 E004.1** (change approval records) and **SOC 2 CC6.3** (segregation
  of duties) are supported in part: the agent cannot approve its own
  destructive change.
* **EU AI Act Article 14(1)** (human oversight of high-risk AI systems while
  in use): a precondition is a built-in oversight measure for destructive
  actions, and the bound decision proves it operated. Article 14 applies only
  to high-risk systems, and nothing here is a claim of conformity.

## 10. Intended for standardisation

This specification is offered as input to the IETF SCITT (Supply Chain
Integrity, Transparency and Trust) work on receipts for AI agent actions, and
to any other effort defining verifiable records of agent behaviour. The
pattern it describes, "a signed, expiring, scoped proof that a safeguard
held, required by and bound into the record of a destructive agent action",
is independent of Perathos's file formats: the precondition could be carried
as a COSE-signed statement registered with a SCITT transparency service, and
the `guard` binding as a claim in the action's receipt. The authors welcome
review, alternative encodings and interoperable implementations; please open
an issue on the repository.

## 11. Test vectors

The reference test suite (`tests/test_anchor_guard.py`,
`tests/test_guard_hardening.py`) exercises creation, tamper detection,
untrusted signers, expiry and whole-token scope matching. Independent
implementations SHOULD reproduce a precondition hash from a precondition file
created by `perathos precondition add` and verify its signature with only a
SHA-256 and an Ed25519 library.
