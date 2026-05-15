"""Test public API aliases and usage patterns from README."""
from perathos import prove, verify, sign, inspect, generate_keypair


def test_prove_alias_works():
    bundle = prove("The capital of France is Paris.", input_text="What is the capital of France?")
    assert "bundle_id" in bundle
    assert "integrity_hash" in bundle


def test_verify_alias_works():
    bundle = prove("output text")
    valid, err = verify(bundle)
    assert valid is True
    assert err == ""


def test_sign_alias_works():
    bundle = prove("output text")
    sk, vk = generate_keypair()
    signed = sign(bundle, sk)
    assert "provider_signature" in signed
    assert signed["provider_signature"]["verify_key"] == vk


def test_inspect_alias_callable():
    bundle = prove("output text")
    # inspect doesn't return anything, just ensure it's callable and doesn't crash
    try:
        inspect(bundle)
    except Exception as exc:
        assert False, f"inspect() raised unexpected exception: {exc}"


def test_readme_example_pattern():
    """Test the exact usage pattern from README.md"""
    bundle = prove("The capital of France is Paris.", input_text="What is the capital of France?")
    sk, _ = generate_keypair()
    bundle = sign(bundle, sk)
    valid, err = verify(bundle)
    assert valid is True
    assert err == ""
