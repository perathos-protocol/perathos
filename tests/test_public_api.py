"""Test that the public Python API exports work correctly."""
import perathos


def test_prove_alias_exists():
    """Test that prove is exported at the top level."""
    assert hasattr(perathos, 'prove')
    assert callable(perathos.prove)


def test_verify_alias_exists():
    """Test that verify is exported at the top level."""
    assert hasattr(perathos, 'verify')
    assert callable(perathos.verify)


def test_sign_alias_exists():
    """Test that sign is exported at the top level."""
    assert hasattr(perathos, 'sign')
    assert callable(perathos.sign)


def test_inspect_alias_exists():
    """Test that inspect is exported at the top level."""
    assert hasattr(perathos, 'inspect')
    assert callable(perathos.inspect)


def test_prove_is_create_bundle():
    """Test that prove is an alias for create_bundle."""
    assert perathos.prove is perathos.create_bundle


def test_sign_is_sign_bundle():
    """Test that sign is an alias for sign_bundle."""
    assert perathos.sign is perathos.sign_bundle


def test_verify_is_verify_bundle():
    """Test that verify is an alias for verify_bundle."""
    assert perathos.verify is perathos.verify_bundle


def test_inspect_is_inspect_bundle():
    """Test that inspect is an alias for inspect_bundle."""
    assert perathos.inspect is perathos.inspect_bundle


def test_prove_api_works():
    """Test that the prove() API works end-to-end."""
    bundle = perathos.prove("Hello world")
    assert bundle["bundle_id"]
    assert bundle["output_hash"]


def test_verify_api_works():
    """Test that the verify() API works end-to-end."""
    bundle = perathos.prove("Test output")
    valid, err = perathos.verify(bundle)
    assert valid is True
    assert err == ""


def test_sign_api_works():
    """Test that the sign() API works end-to-end."""
    bundle = perathos.prove("Test output")
    sk, vk = perathos.generate_keypair()
    signed_bundle = perathos.sign(bundle, sk)
    assert "provider_signature" in signed_bundle


def test_all_exports_in_all():
    """Test that the public API exports are in __all__."""
    for name in ["prove", "verify", "sign", "inspect"]:
        assert name in perathos.__all__
