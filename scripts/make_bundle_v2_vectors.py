#!/usr/bin/env python
"""Generate the Bundle v2 commerce-event test vectors (for the NEXUS trust record).

Writes docs/specs/vectors/bundle_v2/ (or --out DIR): one folder per case
holding ``bundle.json``, plus ``jwks.json`` (the trusted key) and
``expected.json`` (every intermediate value and the verdict each case must get).

The bundles model NEXUS commerce events (``model`` ``nexus.commerce.event/1``):
``answer`` is the canonical JSON of the event payload, and ``input_text`` is the
previous event's ``bundle_id`` for the same order ("" for the first), which
chains one order's events together. ``create_bundle`` cannot produce these (it
reads the clock and fixes the model descriptor), so this script builds each
bundle field by field from public functions only: ``canonical_bytes``,
``PERATHOS_NAMESPACE``, ``sign_hash``, ``kid_for`` and ``TrustStore.to_jwks``.
``create_bundle`` is untouched.

Fixed keys, a fixed ``issued_at`` per event and fixed payloads make the output
deterministic (Ed25519 signatures are deterministic), so re-running produces
byte-identical files.

Usage:
    python scripts/make_bundle_v2_vectors.py [--out DIR]

The signing keys below are published on purpose. Never use them for anything real.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import uuid
from pathlib import Path

# Allow running from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from perathos.bundle import PERATHOS_NAMESPACE, verify_bundle  # noqa: E402
from perathos.canonical import canonical_bytes  # noqa: E402
from perathos.keytrust import TrustStore, kid_for  # noqa: E402
from perathos.signing import sign_hash  # noqa: E402

DEFAULT_OUT = (
    Path(__file__).resolve().parent.parent / "docs" / "specs" / "vectors" / "bundle_v2"
)

# FIXED TEST KEYS, published on purpose. Never use them for anything real.
# RFC 8032 section 7.1, TEST 1 / TEST 2 / TEST 3 secret keys.
TEST_KEYS = {
    "trusted": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "forger": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "outsider": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
}

MODEL = "nexus.commerce.event/1"
MODEL_DESCRIPTOR = "nexus-platform:nexus.commerce.event:v1"
PROOF_SYSTEM = "sha256-deterministic"
BUNDLE_VERSION = "2.0"
BUNDLE_FILE = "bundle.json"

# An opaque order reference as NEXUS makes it: "or_" + 128 bits of HMAC (here, of nothing real).
ORDER_REF = (
    "or_" + hashlib.sha256(b"nexus trust record test vector order").hexdigest()[:32]
)

_BASE = {
    "schema": MODEL,
    "order_ref": ORDER_REF,
    "total_cents": 12900,
    "currency": "ZAR",
    "item_count": 3,
    "evidence": "recorded",
}

# The valid chain for one order: (case, payload fields, issued_at).
CHAIN = (
    (
        "01-order-confirmed",
        {
            "event": "order.confirmed",
            "seq": 1,
            "actor": "payment_provider",
            "occurred_at": "2026-11-22T09:14:03.120Z",
        },
        "2026-11-22T09:14:04.000Z",
    ),
    (
        "02-order-shipped",
        {
            "event": "order.shipped",
            "seq": 2,
            "actor": "owner",
            "occurred_at": "2026-11-23T10:00:00.000Z",
        },
        "2026-11-23T10:00:00.250Z",
    ),
    (
        "03-order-delivered",
        {
            "event": "order.delivered",
            "seq": 3,
            "actor": "owner",
            "occurred_at": "2026-11-25T15:30:00.000Z",
        },
        "2026-11-25T15:30:00.900Z",
    ),
    (
        "04-dispute-closed",
        {
            "event": "order.dispute_closed",
            "seq": 4,
            "actor": "payment_provider",
            "occurred_at": "2026-12-20T08:00:00.000Z",
            "outcome": "won",
        },
        "2026-12-20T08:00:01.000Z",
    ),
)

TAMPERED = (
    "10-answer-edited",
    "11-output-hash-edited",
    "12-trace-edited",
    "13-bundle-id-edited",
    "14-forged-signature",
    "15-signature-removed",
    "16-algorithm-changed",
    "17-untrusted-signer",
    "18-answer-stripped",
    "19-chain-broken",
    "20-trace-float-encoding",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _flip_last_hex(h: str) -> str:
    return h[:-1] + ("0" if h[-1] != "0" else "1")


def _public_hex(key_name: str) -> str:
    return sign_hash("0" * 64, TEST_KEYS[key_name])["verify_key"]


def build(
    payload: dict, input_text: str, issued_at: str, signer: str
) -> tuple[dict, dict]:
    """Build and sign one bundle field by field. Returns (bundle, intermediates)."""
    payload_bytes = canonical_bytes(payload)
    output_text = payload_bytes.decode("utf-8")
    trace = {
        "model_descriptor": MODEL_DESCRIPTOR,
        "proof_system": PROOF_SYSTEM,
        "input_length": len(input_text),
        "output_length": len(output_text),
    }
    trace_bytes = canonical_bytes(trace)
    integrity_payload = {
        "ai_id": _sha256(MODEL_DESCRIPTOR.encode("utf-8")),
        "input_hash": _sha256(input_text.encode("utf-8")),
        "issued_at": issued_at,
        "output_hash": _sha256(payload_bytes),
        "proof_system": PROOF_SYSTEM,
        "trace_hash": _sha256(trace_bytes),
        "bundle_version": BUNDLE_VERSION,
        "model": MODEL,
    }
    ip_bytes = canonical_bytes(integrity_payload)
    integrity_hash = _sha256(ip_bytes)
    bundle_id = str(uuid.uuid5(PERATHOS_NAMESPACE, integrity_hash))
    signature = sign_hash(integrity_hash, TEST_KEYS[signer])
    # Same field order as create_bundle's v2 output.
    bundle = {
        "bundle_id": bundle_id,
        "proof_system": PROOF_SYSTEM,
        "issued_at": issued_at,
        "ai_id": integrity_payload["ai_id"],
        "input_hash": integrity_payload["input_hash"],
        "output_hash": integrity_payload["output_hash"],
        "trace_hash": integrity_payload["trace_hash"],
        "integrity_hash": integrity_hash,
        "_trace": trace,
        "bundle_version": BUNDLE_VERSION,
        "model": MODEL,
        "answer": output_text,
        "provider_signature": signature,
    }
    intermediates = {
        "payload": payload,
        "payload_canonical": output_text,
        "payload_canonical_hex": payload_bytes.hex(),
        "input_text": input_text,
        "issued_at": issued_at,
        "signer": signer,
        "_trace": trace,
        "trace_canonical": trace_bytes.decode("utf-8"),
        "trace_hash": integrity_payload["trace_hash"],
        "ai_id": integrity_payload["ai_id"],
        "input_hash": integrity_payload["input_hash"],
        "output_hash": integrity_payload["output_hash"],
        "integrity_payload": integrity_payload,
        "integrity_payload_canonical": ip_bytes.decode("utf-8"),
        "integrity_payload_canonical_hex": ip_bytes.hex(),
        "integrity_hash": integrity_hash,
        "bundle_id": bundle_id,
        "provider_signature": signature,
    }
    return bundle, intermediates


def _trust_store() -> TrustStore:
    return TrustStore().add_public_key(bytes.fromhex(_public_hex("trusted")))


def _cases() -> tuple[dict, dict]:
    """Every case: name -> (bundle, record). Plus the chains."""
    out: dict[str, tuple[dict, dict]] = {}
    prev_id = ""
    chain_builds = {}
    for name, fields, issued_at in CHAIN:
        payload = {**_BASE, **fields}
        bundle, inter = build(payload, prev_id, issued_at, "trusted")
        chain_builds[name] = (bundle, inter)
        out[name] = (
            bundle,
            {
                "kind": "valid",
                "description": f"seq {fields['seq']} of the order: {fields['event']}"
                + (
                    f" with outcome {fields['outcome']!r}"
                    if "outcome" in fields
                    else ""
                )
                + (
                    ', the first event, so input_text is ""'
                    if not prev_id
                    else ", input_text is the previous event's bundle_id"
                ),
                "derived_from": None,
                "mutation": None,
                "build": inter,
                "python": {"verdict": "VALID", "code": ""},
                "nexus": {"verdict": "VALID", "code": ""},
            },
        )
        prev_id = bundle["bundle_id"]

    base_bundle, base_inter = chain_builds["01-order-confirmed"]

    def mutated(name: str, mutation: str, fn, code: str, description: str) -> None:
        b = copy.deepcopy(base_bundle)
        fn(b)
        out[name] = (
            b,
            {
                "kind": "tampered",
                "description": description,
                "derived_from": "01-order-confirmed",
                "mutation": mutation,
                "build": base_inter,
                "python": {"verdict": "INVALID", "code": code},
                "nexus": {"verdict": "INVALID", "code": code},
            },
        )

    def edit_answer(b):
        b["answer"] = b["answer"].replace('"total_cents":12900', '"total_cents":12901')

    def edit_output_hash(b):
        b["output_hash"] = _flip_last_hex(b["output_hash"])

    def edit_trace(b):
        b["_trace"]["output_length"] += 1

    def edit_bundle_id(b):
        b["bundle_id"] = _flip_last_hex(b["bundle_id"])

    def forge_signature(b):
        forged = sign_hash(b["integrity_hash"], TEST_KEYS["forger"])
        b["provider_signature"]["signature"] = forged["signature"]

    def remove_signature(b):
        del b["provider_signature"]

    def change_algorithm(b):
        b["provider_signature"]["algorithm"] = "ed448"

    def strip_answer(b):
        del b["answer"]

    mutated(
        "10-answer-edited",
        'answer: "total_cents":12900 -> "total_cents":12901',
        edit_answer,
        "ERR_ANSWER_MISMATCH",
        "answer edited after signing; output_hash still binds the original payload.",
    )
    mutated(
        "11-output-hash-edited",
        "output_hash: last hex digit changed",
        edit_output_hash,
        "ERR_INTEGRITY_HASH_MISMATCH",
        "output_hash edited; it is bound into integrity_hash.",
    )
    mutated(
        "12-trace-edited",
        "_trace.output_length: +1",
        edit_trace,
        "ERR_TRACE_HASH_MISMATCH",
        "_trace edited; it no longer hashes to trace_hash.",
    )
    mutated(
        "13-bundle-id-edited",
        "bundle_id: last hex digit changed",
        edit_bundle_id,
        "ERR_BUNDLE_ID_MISMATCH",
        "bundle_id edited; it is uuid5(PERATHOS_NAMESPACE, integrity_hash).",
    )
    mutated(
        "14-forged-signature",
        "provider_signature.signature: made with the forger key; verify_key unchanged",
        forge_signature,
        "ERR_BAD_SIGNATURE",
        "A well-formed Ed25519 signature over integrity_hash from another key; verify_key still names the trusted key.",
    )
    mutated(
        "15-signature-removed",
        "provider_signature: removed",
        remove_signature,
        "ERR_UNSIGNED",
        "No provider_signature; fails because signatures are required (require_signed / CLI default).",
    )
    mutated(
        "16-algorithm-changed",
        'provider_signature.algorithm: "ed25519" -> "ed448"',
        change_algorithm,
        "ERR_UNSUPPORTED_ALGORITHM",
        "provider_signature.algorithm is not ed25519.",
    )

    # 17: a correct bundle, signed by a key that is not in jwks.json.
    payload1 = base_inter["payload"]
    b17, inter17 = build(payload1, "", base_inter["issued_at"], "outsider")
    out["17-untrusted-signer"] = (
        b17,
        {
            "kind": "tampered",
            "description": "Built exactly like 01 but signed by the outsider key, which is not in jwks.json.",
            "derived_from": None,
            "mutation": None,
            "build": inter17,
            "python": {"verdict": "INVALID", "code": "ERR_UNTRUSTED_SIGNER"},
            "nexus": {"verdict": "INVALID", "code": "ERR_UNTRUSTED_SIGNER"},
        },
    )

    mutated(
        "18-answer-stripped",
        "answer: removed",
        strip_answer,
        "ERR_ANSWER_REQUIRED",
        'answer removed. Python checks answer only when present, so verify_bundle returns (True, ""). '
        "NEXUS requires answer for model nexus.commerce.event/1 (TRUST_RECORD.md section 4.1, D3): "
        "without it the bundle carries only a hash and nobody can read what was attested.",
    )
    out["18-answer-stripped"][1]["python"] = {"verdict": "VALID", "code": ""}

    # 19: seq 2 whose input_text is not seq 1's bundle_id.
    name2, fields2, issued2 = CHAIN[1]
    wrong_prev = _flip_last_hex(base_bundle["bundle_id"])
    b19, inter19 = build({**_BASE, **fields2}, wrong_prev, issued2, "trusted")
    out["19-chain-broken"] = (
        b19,
        {
            "kind": "tampered",
            "description": "seq 2 (order.shipped) built and signed correctly, but its input_text is not "
            "01-order-confirmed's bundle_id (last hex digit changed). Python verifies one bundle at a time "
            "and accepts it; a chain check over [01-order-confirmed, 19-chain-broken] fails because "
            "input_hash != sha256(previous bundle_id).",
            "derived_from": None,
            "mutation": None,
            "build": inter19,
            "python": {"verdict": "VALID", "code": ""},
            "nexus": {"verdict": "INVALID", "code": "ERR_CHAIN"},
        },
    )

    # 20: 01 with _trace.input_length written as 0.0 in the JSON text. Python
    # reads a float and canonicalises it as 0.0, so trace_hash no longer matches;
    # NEXUS refuses any non-integer number token before hashing. json.dumps
    # cannot write 0.0 for the int 0, so the file text is patched (see _file_text).
    out["20-trace-float-encoding"] = (
        copy.deepcopy(base_bundle),
        {
            "kind": "tampered",
            "description": "01-order-confirmed with _trace.input_length written as 0.0 instead of 0 "
            "(the file text only; the value is numerically equal). Python parses a float, canonical JSON "
            "writes 0.0, and the trace hash no longer matches. NEXUS rejects any number token with a "
            "'.', 'e', 'E' or '-0' before hashing, so it never reports VALID where Python reports a "
            "hash mismatch.",
            "derived_from": "01-order-confirmed",
            "mutation": '_trace.input_length: 0 -> 0.0 (JSON text)',
            "build": base_inter,
            "python": {"verdict": "INVALID", "code": "ERR_TRACE_HASH_MISMATCH"},
            "nexus": {"verdict": "INVALID", "code": "ERR_MALFORMED_BUNDLE"},
        },
    )

    chains = {
        "valid": [name for name, _, _ in CHAIN],
        "broken": ["01-order-confirmed", "19-chain-broken"],
    }
    return out, chains


def _expected(cases: dict, chains: dict) -> dict:
    keys = {}
    for name, sk in TEST_KEYS.items():
        vk = _public_hex(name)
        keys[name] = {
            "signing_key": sk,
            "verify_key": vk,
            "kid": kid_for(bytes.fromhex(vk)),
            "in_jwks": name == "trusted",
        }
    return {
        "format": "perathos bundle v2 (bundle_version 2.0), NEXUS commerce event mapping",
        "generator": "scripts/make_bundle_v2_vectors.py",
        "model": MODEL,
        "model_descriptor": MODEL_DESCRIPTOR,
        "proof_system": PROOF_SYSTEM,
        "perathos_namespace": str(PERATHOS_NAMESPACE),
        "jwks": "jwks.json",
        "keys": keys,
        "test_keys_note": "FIXED TEST KEYS (RFC 8032 section 7.1 TEST 1-3), published on purpose. "
        "Never use them for anything real.",
        "python_verify": "verify_bundle(bundle, trust_store=TrustStore.from_jwks(jwks.json), require_signed=True)",
        "chains": chains,
        "cases": {
            name: {"file": f"{name}/{BUNDLE_FILE}", **record}
            for name, (_, record) in cases.items()
        },
    }


def _dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _file_text(name: str, bundle: dict) -> bytes:
    """The bundle file. Case 20 differs from json.dumps only in one number token."""
    text = _dump(bundle)
    if name == "20-trace-float-encoding":
        old, new = b'"input_length": 0,', b'"input_length": 0.0,'
        assert text.count(old) == 1
        text = text.replace(old, new)
    return text


def generate(out: Path) -> None:
    cases, chains = _cases()
    ts = _trust_store()
    for name, (bundle, record) in cases.items():
        # Verify what a reader of the file gets, not the in-memory dict.
        parsed = json.loads(_file_text(name, bundle))
        ok, err = verify_bundle(parsed, trust_store=ts, require_signed=True)
        want = record["python"]
        assert (ok, err) == (want["verdict"] == "VALID", want["code"]), (name, ok, err)
    out.mkdir(parents=True, exist_ok=True)
    for name, (bundle, _) in cases.items():
        (out / name).mkdir(parents=True, exist_ok=True)
        (out / name / BUNDLE_FILE).write_bytes(_file_text(name, bundle))
    (out / "jwks.json").write_bytes(_dump(ts.to_jwks()))
    (out / "expected.json").write_bytes(_dump(_expected(cases, chains)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output directory (default: %(default)s)",
    )
    args = ap.parse_args()
    generate(args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
