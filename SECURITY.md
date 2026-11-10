# Security Policy

_Last updated: 2026-11-10._

This is the vulnerability disclosure policy for Perathos: the `perathos`
package, the Perathos Gate server, and the hosted Gate. The full security
model, with what is and is not protected, is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Use either channel. Both are private.

- **Email:** hello@perathos.com, with a subject line starting `SECURITY:`.
- **GitHub private vulnerability reporting:** the "Report a vulnerability"
  button on the Security tab of
  [perathos-protocol/perathos](https://github.com/perathos-protocol/perathos/security/advisories/new)
  or
  [perathos-protocol/perathos-gate](https://github.com/perathos-protocol/perathos-gate/security/advisories/new).

Please include a description, the affected version or commit, and steps to
reproduce. A proof of concept helps. Do not open a public issue, pull request
or discussion for a security report.

If the report concerns the hosted Gate, say so in the first line, and do not
include other people's data in the report.

## What to expect

These are targets, not promises. Perathos has one maintainer.

| Step | Target |
|---|---|
| Acknowledgement of your report | within 5 working days |
| Initial assessment (valid or not, severity) | within 10 working days of the acknowledgement |
| Fix or mitigation for a confirmed issue | as fast as the severity warrants; we will tell you the plan |
| Public disclosure | coordinated with you; by default when a fixed release is published, or 90 days after the report, whichever is first |

We credit reporters in the CHANGELOG and the release notes unless you ask us
not to.

**There are no bug bounty payments at this time.** We cannot pay for reports.

## Scope

In scope:

- **`perathos`** (this repository): the flight recorder, the guard and
  preconditions, anchors, evidence packs, remote signers and approver keys, the
  Gate client and receipt verifier, the hooks for Claude Code and Cursor, the
  MCP proxy and MCP server, proof bundles (construction, signing, verification,
  canonical serialisation, the verifier pipeline), the CLI, and the browser
  verifier under `site/verify/`.
- **`perathos-gate`** (<https://github.com/perathos-protocol/perathos-gate>):
  the Gate server, its approver and enrolment pages, and its admin CLI.
- **The hosted Gate** at `gate.perathos.com`, within the rules below.

Examples of what we want to hear about:

- a way to alter a sealed log, an evidence pack, a precondition or a Gate
  receipt without the verifier noticing;
- a way to make a verifier accept a forged signature or timestamp;
- a destructive command of the accident class (the plain form a person would
  type) that the guard lets through;
- a way to approve a Gate request without an enrolled passkey, to read or
  decide another organisation's requests, or to recover an API key, approve
  link or enrolment link from the server;
- a hook or proxy path that allows a call the guard denied.

## Out of scope

The published known limits are not vulnerabilities in themselves. They are
listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (sections 5 to 7),
[docs/specs/RECEIPT_V1.md](docs/specs/RECEIPT_V1.md) and
[docs/FOR_AUDITORS.md](docs/FOR_AUDITORS.md). In particular:

- the guard is a pattern matcher and not a sandbox, so a deliberately
  disguised command getting past it is expected;
- with the default local key, a process that can read the key file can forge
  records and approvals;
- a period with hooks switched off leaves no trace in the log;
- the `model` field is self-reported, and times are local-clock unless
  anchored;
- whoever controls a Gate server's signing key can issue receipts that verify
  against that key;
- passkeys may be synced between devices, and the Gate does not claim device
  binding;
- an approver can be persuaded to approve something they should not.

A report that shows one of these limits is worse than documented, or that a
documented mitigation does not work, is in scope.

Also out of scope: the optional NLI model weights (third-party); the
autonomous-agent harness under `org/` (repository tooling, not part of the
shipped package); findings that need a compromised operator machine or
administrator rights to begin with; missing hardening headers or best-practice
notes with no demonstrated impact; and volumetric denial of service.

## Rules for testing the hosted Gate

- Test only against organisations and approvers you created or were given for
  testing. Ask at hello@perathos.com if you need a test organisation.
- Do not access, change or delete other people's data. If you come across any,
  stop and report it.
- No denial-of-service testing, load testing or automated scanning at volume.
  The hosted Gate is a single small deployment.
- No social engineering of the maintainer, approvers or users, and no physical
  attacks.

For anything that needs heavier testing, run your own Gate from the
`perathos-gate` repository.

## Safe harbour

If you make a good-faith effort to follow this policy, we will:

- treat your research as authorised by us, and not start or support legal
  action against you for it;
- not report you to law enforcement for it;
- work with you to understand and fix the issue.

Good faith means: you stay within the scope and the testing rules above, you
avoid privacy violations and disruption to others, you give us a reasonable
time to fix the issue before publishing, and you do not exploit it beyond what
is needed to show that it exists.

This is a statement of our intent. We cannot bind third parties (for example
a hosting provider or a Time Stamping Authority), and it does not authorise
testing of their systems. If you are unsure whether something is covered, ask
first.

## Supported versions

| Version | Supported |
|---|---|
| `perathos` 1.x, latest minor release | Yes: security fixes are released as a new 1.x patch or minor version |
| `perathos` 1.x, older minors | Upgrade to the latest 1.x; fixes are not backported |
| `perathos` < 1.0 | No |
| `perathos-gate` | The `main` branch |

Releases of `perathos` are published to PyPI from a tagged commit by GitHub
Actions with PyPI trusted publishing. From the release after 1.1.0, each
release also carries a build provenance attestation and a CycloneDX SBOM; see
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) for how to verify
them.

## Security model in brief

Perathos records are **tamper-evident**, and they are **evidence, not a
guarantee**. Every receipt in a flight-recorder log is SHA-256 hash-chained to
the previous one and sealed by Ed25519-signed checkpoints, optionally
timestamped by an RFC 3161 authority. Preconditions and evidence-pack
manifests are signed the same way. A Gate receipt carries a passkey assertion
over a hash of the request and the decision, and the Gate server's Ed25519
signature. Verification recomputes the hashes and checks the signatures
offline.

What that does not give you is set out in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Two points matter most: **pin
the signer's public key, and the Gate key, out of band** (a bare signature
does not establish identity), and **keep signing keys away from the agent**
(with the default local key, an agent that can read the key can forge).

## Cryptography

- Hashing: SHA-256.
- Signatures: Ed25519 (the `cryptography` library). Passkey signatures in Gate
  receipts: ES256, EdDSA or RS256.
- Timestamps: RFC 3161, accepted only when they chain to a pinned TSA root.
- Serialisation: deterministic canonical JSON (sorted string keys, compact,
  UTF-8, no NaN or Infinity).

## Key handling

- The default signing key is written atomically and restricted to the owner
  (POSIX `0o600`; Windows owner-only ACL via `icacls`, best effort with a
  warning on failure).
- It is stored as cleartext hex under `~/.perathos/keys/`, on the same machine
  as the agent. Remote signers (`vault:`, `gcpkms:`, `command:`) and separate
  approver keys move keys off the machine; see the threat model, section 8.

## What a `PASS` does and does not mean

A `PASS` verdict on a proof bundle means the configured verifiers found no
problem given the available evidence. It is evidence, not a guarantee of
truth. Detection has false negatives. `INCONCLUSIVE` means "not enough
evidence" and must not be treated as `PASS`.
