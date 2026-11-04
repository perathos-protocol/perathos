"""Unsigned bundles: library opt-in gate and MCP default rejection."""
import asyncio
import json

from perathos import create_bundle, sign_bundle, verify
from perathos.signing import generate_keypair


def test_library_default_unchanged_for_unsigned():
    ok, err = verify(create_bundle("x"))
    assert ok and err == ""


def test_library_require_signed_rejects_unsigned():
    ok, err = verify(create_bundle("x"), require_signed=True)
    assert not ok and err == "ERR_UNSIGNED"


def test_library_require_signed_accepts_signed():
    sk, _vk = generate_keypair()
    signed = sign_bundle(create_bundle("x"), sk)
    ok, err = verify(signed, require_signed=True)
    assert ok, err


def test_tampered_unsigned_reports_tamper_not_unsigned():
    b = create_bundle("x")
    b["output_hash"] = "0" * 64
    ok, err = verify(b, require_signed=True)
    assert not ok and err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_mcp_verify_rejects_unsigned_by_default():
    from perathos.mcp_server import VerifyBundleInput, perathos_verify_bundle
    bundle_json = json.dumps(create_bundle("x"))
    out = json.loads(asyncio.run(perathos_verify_bundle(VerifyBundleInput(bundle_json=bundle_json))))
    assert out["valid"] is False and out["error_code"] == "ERR_UNSIGNED"
    out = json.loads(asyncio.run(perathos_verify_bundle(VerifyBundleInput(bundle_json=bundle_json, allow_unsigned=True))))
    assert out["valid"] is True
