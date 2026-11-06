# Perathos Gate v1: human approval for irreversible agent actions

Status: draft, 2026-11-06. Reference implementations: `perathos/gate.py` (client and
verifier, in this repo) and the `perathos-gate` server.

## Purpose

An AI agent is about to do something that cannot be undone: delete data, move money, send
mail to customers, deploy, change permissions. Gate lets it ask a named person for approval,
lets that person approve or deny **on their own device with a passkey**, and returns a
receipt that anyone can verify offline. The receipt proves three things:

1. **What** was approved: the exact action, bound by hash into the WebAuthn challenge.
2. **Who** approved: a person's passkey (a hardware-backed key on their phone or security key)
   signed it, with user verification (biometric or PIN), not just a click.
3. **When**, and that the Gate server recorded it: the server signs the whole receipt.

This is the evidence AIUC-1 control D003.4 asks for ("requiring human approval for sensitive
tool operations ... deleting or irreversibly modifying records"), produced at the moment of
the decision, by the approver's own hardware.

## Roles

- **Agent side**: the Perathos guard (Claude Code, Cursor, MCP proxy) or any program using the
  API with an organisation API key.
- **Gate server**: stores requests, notifies approvers, runs the WebAuthn ceremony, signs
  receipts with its Ed25519 key. It cannot approve on anyone's behalf: approval requires an
  approver's passkey signature.
- **Approver**: a person enrolled with a passkey.

## Canonical encoding and hashes

Canonical JSON as in `RECEIPT_V1.md` (sorted keys, no whitespace, UTF-8, no floats).
`H(x)` = lowercase hex SHA-256 of canonical JSON of `x`.

### The request

```json
{
  "v": "perathos.gate.request/v1",
  "id": "apr_<26 base32 chars>",
  "org": "<org id>",
  "gate": "<gate id>",
  "action": {
    "tool": "Bash",
    "summary": "railway volume delete pg-data --yes",
    "rule": "paas.railway",
    "detail": "<optional longer text shown to the approver, max 4000 chars>",
    "target": "<optional scope token, e.g. pg-data>"
  },
  "agent": {"name": "claude-code", "session_id": "<id>", "host": "<hostname>"},
  "args_hash": "<64 hex: perathos content_hash of the tool arguments>",
  "created_at": "2026-11-06T10:00:00Z",
  "expires_at": "2026-11-06T10:10:00Z"
}
```

`request_hash = H(request)`.

### The decision challenge

For decision `d` in `{"approve", "deny"}`:

```
challenge = SHA-256 bytes of canonical JSON {"decision": d, "request_hash": request_hash, "v": "perathos.gate.challenge/v1"}
```

This 32-byte value is the WebAuthn challenge. Approving and denying produce different
challenges, so an approval cannot be replayed as a denial or vice versa, and an approval of
one request cannot be used for another.

### The receipt

```json
{
  "v": "perathos.gate.receipt/v1",
  "request": { ...the request object... },
  "request_hash": "<64 hex>",
  "decision": "approve",
  "decided_at": "2026-11-06T10:02:13Z",
  "valid_until": "2026-11-06T10:12:13Z",
  "approver": {
    "name": "Alice Moyo",
    "credential_id": "<base64url>",
    "public_key": "<base64url of the DER SubjectPublicKeyInfo>",
    "alg": -7,
    "enrolled_at": "2026-11-01T09:00:00Z"
  },
  "rp": {"id": "gate.example.com", "origin": "https://gate.example.com"},
  "webauthn": {
    "authenticator_data": "<base64url>",
    "client_data_json": "<base64url>",
    "signature": "<base64url>"
  },
  "receipt_hash": "<64 hex: H(receipt without receipt_hash and server_signature)>",
  "server_signature": {"algorithm": "ed25519", "verify_key": "<64 hex>", "signature": "<128 hex>"}
}
```

`valid_until` bounds how long the approval may be used to execute the action (default 10
minutes after the decision). A denial has the same shape with `"decision": "deny"`.

## Receipt verification (offline)

A verifier MUST check, in order:

1. `receipt_hash` recomputes; `server_signature` verifies over its 32 raw bytes; the
   signature key equals the Gate key the verifier pinned (from `/.well-known/perathos-gate.json`
   at enrolment time, or configured by hand).
2. `request_hash == H(request)`.
3. `client_data_json` decodes to JSON with `type == "webauthn.get"`,
   `challenge == base64url(challenge(decision, request_hash))` (unpadded) and
   `origin == rp.origin`.
4. `authenticator_data` is at least 37 bytes; its first 32 bytes equal SHA-256 of `rp.id`;
   flags byte has User Present (0x01) and User Verified (0x04) set.
5. The approver public key verifies `signature` over
   `authenticator_data || SHA-256(client_data_json bytes)`, using ES256 (`alg -7`, ECDSA P-256
   with SHA-256, DER signature), EdDSA (`alg -8`, Ed25519) or RS256 (`alg -257`).
6. For use by a guard: `decision == "approve"`, now is before `valid_until`, the request's
   `args_hash` equals the hash of the arguments about to run, and the receipt has not been used
   before (the guard records the receipt hash in its action receipt).

## HTTP API (server)

All agent-side calls send `Authorization: Bearer <org api key>`. JSON in and out.

| Method and path | Purpose |
|---|---|
| `GET /.well-known/perathos-gate.json` | `{"gate": id, "verify_key": hex, "rp_id", "origin", "version"}`. No auth. |
| `POST /v1/approvals` | Body: `{action, agent, args_hash, ttl_seconds?}` (ttl 60..3600, default 600). Creates the request, notifies approvers. Returns `201 {id, status: "pending", request, approve_url, expires_at}`. |
| `GET /v1/approvals/{id}?wait=N` | Long-poll up to N seconds (max 60) while pending. Returns `{id, status, receipt?}`; `status` is `pending`, `approved`, `denied` or `expired`. |
| `GET /a/{id}?t=<token>` | Approver page (HTML): shows the action, Approve and Deny buttons. |
| `POST /a/{id}/options` | Body `{t, decision}` → WebAuthn assertion options with the decision challenge and the org's approver credentials. |
| `POST /a/{id}/verify` | Body `{t, decision, credential}` → verifies the assertion, records the decision, builds and signs the receipt. |
| `GET /enroll/{token}` | Approver enrolment page; `POST /enroll/{token}/options` and `/verify` register a passkey (user verification required). |

Notification: if the organisation has a webhook URL, the server POSTs
`{"text": "<agent> wants to <summary>. Approve or deny: <approve_url>"}` (Slack-compatible).

## Security considerations

- The server never holds approvers' private keys. A compromised server can refuse, delay or
  forge *server* signatures, but cannot produce an approver's WebAuthn signature; verifiers check
  both.
- The approval page shows the action text the agent supplied. The agent could describe an action
  misleadingly; the guard binds `args_hash` to the real arguments, and the approver sees the
  command text the guard extracted, not the agent's own description.
- Command text is sent to the Gate server so the approver can read it. Organisations that cannot
  send it can set the client to send only the rule and target.
- Enrolment links are single-use, expire in 24 hours, and should be delivered out of band.
