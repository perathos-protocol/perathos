# Security Policy

## Reporting a vulnerability

Email **hello@perathos.com** with the subject line starting `SECURITY:`.
Include a description, the affected version or commit, and a reproduction.
Do not open public issues, pull requests or discussions for security reports.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment (valid / not valid, severity) | within 10 business days |
| Fix or mitigation for a confirmed issue | as fast as severity warrants |
| Public disclosure | coordinated with the reporter; by default **90 days** after the report, or when a fixed release is published, whichever is first |

We credit reporters in the CHANGELOG and the release notes unless asked not to.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest minor release) | Yes: security fixes are released as a new 1.x patch or minor version |
| 1.x older minors | Upgrade to the latest 1.x; fixes are not backported |
| < 1.0 | No |

Releases are published to PyPI from a tagged commit by GitHub Actions with
PyPI trusted publishing. From the release after 1.1.0, each release also
carries a build provenance attestation and a CycloneDX SBOM; see
[docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) for how to verify
them.

## Scope

In scope: the `perathos` package (flight recorder, guard and preconditions,
anchors, evidence packs, bundle construction, signing, verification,
canonical serialization, the verifier pipeline, the MCP proxy and MCP
server), its CLI, and the browser verifier under `site/verify/`. Out of
scope: the optional NLI model weights (third-party), and the autonomous-agent
harness under `org/` (operational tooling, not part of the shipped package or
the verification trust base).

Known, documented limits are not vulnerabilities in themselves (for example,
that the guard matches patterns and is not a sandbox). A bypass of the guard
by an *accident-class* command, a way to alter a sealed log or evidence pack
without detection, or a way to make a verifier accept a forged signature or
timestamp, is in scope.

## Security model in one paragraph

A Perathos record is **tamper-evident**: every receipt in a flight-recorder
log is SHA-256 hash-chained to the previous one and sealed by Ed25519-signed
checkpoints, optionally timestamped by an RFC 3161 authority; proof bundles
fold every significant field into a SHA-256 `integrity_hash` covered by an
optional Ed25519 signature. Verification recomputes the chain and validates
signatures offline. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/specs/RECEIPT_V1.md](docs/specs/RECEIPT_V1.md) for the full model,
including the assumptions a deployment must satisfy (notably: **pin the
signer's public key out of band**; a bare signature does not establish
identity).

## Cryptography

- Hashing: SHA-256.
- Signatures: Ed25519 (the `cryptography` library / pyca).
- Timestamps: RFC 3161, accepted only when they chain to a pinned TSA root.
- Serialization: deterministic canonical JSON (sorted string keys, compact,
  UTF-8, no NaN/Infinity) for reproducible, cross-language verification.

## Key handling

- Private signing keys are written atomically and restricted to the owner
  (POSIX `0o600`; Windows owner-only ACL via `icacls`, best-effort with a
  warning on failure).
- Keys are stored as cleartext hex under `~/.perathos/keys/`. The signing key
  therefore lives on the same machine as the agent unless you keep it
  elsewhere; see the threat model and the signer documentation for options.

## What a `PASS` does and does not mean

A `PASS` verdict means the configured verifiers found no problem given the
available evidence. It is **evidence, not a guarantee of truth**; detection has
false negatives and confidence is calibrated, not absolute. `INCONCLUSIVE`
means "not enough evidence" and must not be treated as `PASS`.
