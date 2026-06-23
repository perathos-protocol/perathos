import uuid


from perathos.bundle import PERATHOS_NAMESPACE, create_bundle, sign_bundle, verify_bundle
from perathos.signing import generate_keypair


def test_create_bundle_has_required_fields():
    b = create_bundle("hello world")
    for field in ("bundle_id", "proof_system", "issued_at", "ai_id",
                  "input_hash", "output_hash", "trace_hash", "integrity_hash", "_trace"):
        assert field in b, f"missing field: {field}"


def test_bundle_id_is_valid_uuid():
    b = create_bundle("some output")
    uid = uuid.UUID(b["bundle_id"])
    assert uid.version == 5


def test_bundle_id_deterministic_from_integrity_hash():
    b = create_bundle("same text")
    expected = str(uuid.uuid5(PERATHOS_NAMESPACE, b["integrity_hash"]))
    assert b["bundle_id"] == expected


def test_verify_valid_bundle():
    b = create_bundle("valid output", input_text="prompt")
    valid, err = verify_bundle(b)
    assert valid is True
    assert err == ""


def test_verify_detects_tampered_output_hash():
    b = create_bundle("output text")
    tampered = dict(b)
    tampered["output_hash"] = "a" * 64
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert "ERR" in err


def test_verify_detects_tampered_trace():
    b = create_bundle("output text")
    tampered = dict(b)
    tampered["_trace"] = {**b["_trace"], "output_length": 999}
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_TRACE_HASH_MISMATCH"


def test_verify_detects_tampered_bundle_id():
    b = create_bundle("output text")
    tampered = dict(b)
    tampered["bundle_id"] = str(uuid.uuid4())
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_BUNDLE_ID_MISMATCH"


def test_verify_missing_trace():
    b = create_bundle("output")
    del b["_trace"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert err == "ERR_MISSING_TRACE"


def test_verify_missing_ai_id():
    b = create_bundle("output")
    del b["ai_id"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "ai_id" in err


def test_verify_missing_input_hash():
    b = create_bundle("output")
    del b["input_hash"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "input_hash" in err


def test_verify_missing_issued_at():
    b = create_bundle("output")
    del b["issued_at"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "issued_at" in err


def test_verify_missing_output_hash():
    b = create_bundle("output")
    del b["output_hash"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "output_hash" in err


def test_verify_missing_proof_system():
    b = create_bundle("output")
    del b["proof_system"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "proof_system" in err


def test_verify_missing_trace_hash():
    b = create_bundle("output")
    del b["trace_hash"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "trace_hash" in err


def test_verify_missing_integrity_hash():
    b = create_bundle("output")
    del b["integrity_hash"]
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR_MISSING_FIELD" in err
    assert "integrity_hash" in err


def test_verify_trace_not_dict():
    """Verify rejects _trace when it is not a dict (e.g., a string or list)."""
    b = create_bundle("output")
    tampered = dict(b)
    tampered["_trace"] = "not a dict"
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert "ERR" in err


def test_verify_trace_is_none():
    """Verify rejects _trace when it is None (not the same as missing)."""
    b = create_bundle("output")
    tampered = dict(b)
    tampered["_trace"] = None
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_MISSING_TRACE"


def test_verify_trace_is_list():
    """Verify rejects _trace when it is a list instead of dict."""
    b = create_bundle("output")
    tampered = dict(b)
    tampered["_trace"] = [1, 2, 3]
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert "ERR" in err


def test_verify_trace_is_empty_dict():
    """Verify rejects _trace when it is an empty dict (hash mismatch)."""
    b = create_bundle("output")
    tampered = dict(b)
    tampered["_trace"] = {}
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_TRACE_HASH_MISMATCH"


def test_sign_bundle_adds_signature():
    b = create_bundle("output text")
    sk, vk = generate_keypair()
    signed = sign_bundle(b, sk)
    assert "provider_signature" in signed
    assert signed["provider_signature"]["verify_key"] == vk
    assert signed["provider_signature"]["algorithm"] == "ed25519"


def test_sign_bundle_does_not_mutate_original():
    b = create_bundle("output text")
    sk, _ = generate_keypair()
    signed = sign_bundle(b, sk)
    assert "provider_signature" not in b
    assert "provider_signature" in signed


def test_empty_input_hash_is_stable():
    b = create_bundle("output")
    b2 = create_bundle("output", input_text="")
    assert b["input_hash"] == b2["input_hash"]


def test_different_outputs_produce_different_bundles():
    b1 = create_bundle("output A")
    b2 = create_bundle("output B")
    assert b1["bundle_id"] != b2["bundle_id"]
    assert b1["output_hash"] != b2["output_hash"]
    assert b1["integrity_hash"] != b2["integrity_hash"]


def test_create_bundle_rejects_non_string_output():
    try:
        create_bundle(None)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "output_text" in str(exc)
        assert "string" in str(exc)


def test_create_bundle_rejects_non_string_input():
    try:
        create_bundle("output", input_text=123)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "input_text" in str(exc)
        assert "string" in str(exc)


def test_create_bundle_rejects_bytes_output():
    try:
        create_bundle(b"bytes output")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "output_text" in str(exc)


def test_create_bundle_rejects_int_output():
    try:
        create_bundle(42)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "output_text" in str(exc)
        assert "int" in str(exc)


def test_create_bundle_rejects_dict_input():
    try:
        create_bundle("output", input_text={"key": "value"})
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "input_text" in str(exc)
        assert "dict" in str(exc)


def test_create_bundle_accepts_empty_strings():
    # Empty strings are valid (e.g., prove-from-output-only)
    b1 = create_bundle("")
    assert b1["output_hash"] is not None
    
    b2 = create_bundle("output", input_text="")
    assert b2["input_hash"] is not None


def test_sign_bundle_rejects_non_dict_bundle():
    sk, _ = generate_keypair()
    try:
        sign_bundle("not a dict", sk)
        assert False, "Expected TypeError"
    except TypeError as exc:
        assert "bundle" in str(exc)
        assert "dict" in str(exc)


def test_sign_bundle_rejects_non_string_key():
    b = create_bundle("output")
    try:
        sign_bundle(b, 12345)
        assert False, "Expected TypeError"
    except TypeError as exc:
        assert "signing_key_hex" in str(exc)
        assert "string" in str(exc)


def test_sign_bundle_rejects_short_key():
    b = create_bundle("output")
    try:
        sign_bundle(b, "abc123")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "64" in str(exc)


def test_sign_bundle_rejects_long_key():
    b = create_bundle("output")
    long_key = "a" * 128
    try:
        sign_bundle(b, long_key)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "64" in str(exc)


def test_sign_bundle_rejects_non_hex_key():
    b = create_bundle("output")
    invalid_key = "z" * 64
    try:
        sign_bundle(b, invalid_key)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "hex" in str(exc)


def test_sign_bundle_rejects_bundle_missing_integrity_hash():
    sk, _ = generate_keypair()
    b = create_bundle("output")
    del b["integrity_hash"]
    try:
        sign_bundle(b, sk)
        assert False, "Expected KeyError"
    except KeyError as exc:
        assert "integrity_hash" in str(exc)


# ── signature verification through verify_bundle (regression: a forged
#    signature on an intact hash chain used to pass verify()) ──────────────────

def test_verify_accepts_validly_signed_bundle():
    b = create_bundle("output text", input_text="prompt")
    sk, vk = generate_keypair()
    signed = sign_bundle(b, sk)
    valid, err = verify_bundle(signed)
    assert valid is True
    assert err == ""


def test_verify_rejects_forged_signature():
    """A bundle with an intact chain but a forged signature must NOT verify."""
    b = create_bundle("output text")
    sk, vk = generate_keypair()
    signed = sign_bundle(b, sk)
    signed["provider_signature"]["signature"] = "0" * 128  # forged
    valid, err = verify_bundle(signed)
    assert valid is False
    assert "ERR" in err


def test_verify_rejects_substituted_signer_when_pinned():
    """With expected_verify_key pinned, a re-sign by a different key is rejected."""
    b = create_bundle("output text")
    honest_sk, honest_vk = generate_keypair()
    attacker_sk, attacker_vk = generate_keypair()
    signed = sign_bundle(b, honest_sk)
    # Attacker strips and re-signs the same hash with their own key.
    resigned = sign_bundle(signed, attacker_sk)
    # Unpinned: signature is internally valid, so it passes (caller must pin).
    assert verify_bundle(resigned) == (True, "")
    # Pinned to the honest key: substitution is detected.
    valid, err = verify_bundle(resigned, expected_verify_key=honest_vk)
    assert valid is False
    assert err == "ERR_UNEXPECTED_SIGNER"


def test_verify_accepts_pinned_matching_signer():
    b = create_bundle("output text")
    sk, vk = generate_keypair()
    signed = sign_bundle(b, sk)
    valid, err = verify_bundle(signed, expected_verify_key=vk)
    assert valid is True
    assert err == ""


def test_verify_does_not_crash_on_mixed_key_trace():
    """A hostile _trace with mixed-type keys must return an error, not crash."""
    b = create_bundle("output")
    b["_trace"] = {1: "a", "b": 2}  # json.dumps(sort_keys=True) would TypeError
    valid, err = verify_bundle(b)
    assert valid is False
    assert "ERR" in err


def test_sign_bundle_rejects_uppercase_hex_key():
    """Hex validation is strict lowercase; uppercase keys are rejected."""
    b = create_bundle("output")
    try:
        sign_bundle(b, "A" * 64)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "hex" in str(exc)


# ── Adversarial crypto-core probes (0.2.6): verify_bundle must NEVER raise ─────

def _reseal(b: dict) -> dict:
    """Recompute trace/integrity/id from current fields — what a forger does to
    make a tampered bundle internally self-consistent (all hashing is public)."""
    from perathos.bundle import _sha256
    from perathos.canonical import canonical_bytes
    b = dict(b)
    b["trace_hash"] = _sha256(canonical_bytes(b["_trace"]))
    ip = {"ai_id": b["ai_id"], "input_hash": b["input_hash"], "issued_at": b["issued_at"],
          "output_hash": b["output_hash"], "proof_system": b["proof_system"],
          "trace_hash": b["trace_hash"]}
    if b.get("bundle_version") == "2.0":
        ip["bundle_version"] = b["bundle_version"]
        ip["model"] = b["model"]
    if b.get("verification") is not None:
        ip["verification_hash"] = _sha256(canonical_bytes(b["verification"]))
    b["integrity_hash"] = _sha256(canonical_bytes(ip))
    b["bundle_id"] = str(uuid.uuid5(PERATHOS_NAMESPACE, b["integrity_hash"]))
    return b


def test_verify_rejects_non_string_answer_without_crashing():
    # A v2 bundle whose `answer` is not a string must not crash the .encode() path.
    b = create_bundle("the answer", model="m", include_answer=True)
    b["answer"] = 1234
    valid, err = verify_bundle(b)
    assert valid is False and "ERR_MALFORMED_BUNDLE" in err


def test_verify_rejects_non_dict_verification_without_crashing():
    # A forged, self-consistent bundle whose `verification` is a string must not
    # crash the later .get() cross-check.
    b = create_bundle("out", model="m", verification={"aggregate": {"verdict": "PASS"}})
    b["verification"] = "not-a-dict"
    valid, err = verify_bundle(_reseal(b))
    assert valid is False and "ERR_MALFORMED_BUNDLE" in err


def test_verify_survives_deeply_nested_trace_dos():
    # A deeply-nested _trace crafted to exhaust the stack during canonicalization
    # must return an error, not raise RecursionError (a DoS on the gateway).
    deep = {"x": 0}
    for _ in range(2000):
        deep = {"x": deep}
    b = create_bundle("out")
    b["_trace"] = deep
    valid, err = verify_bundle(b)
    assert valid is False and "ERR" in err


def test_verify_survives_deeply_nested_verification_dos():
    deep = {"x": 0}
    for _ in range(2000):
        deep = {"x": deep}
    b = create_bundle("out", model="m", verification={"aggregate": {"verdict": "PASS"}})
    b["verification"] = deep
    valid, err = verify_bundle(b)
    assert valid is False and "ERR" in err
