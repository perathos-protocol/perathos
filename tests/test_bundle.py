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
