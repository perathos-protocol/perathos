"""Tests for the KMS-ready signer + TrustStore/JWKS trust anchoring."""
import nacl.signing

from perathos.bundle import create_bundle, sign_bundle, verify_bundle
from perathos.keytrust import (
    KmsSigner,
    LocalSigner,
    TrustStore,
    kid_for,
)


def test_local_signer_signs_verifiable_bundle():
    signer = LocalSigner.generate()
    signed = sign_bundle(create_bundle("output"), signer)
    assert signed["provider_signature"]["algorithm"] == "ed25519"
    assert signed["provider_signature"]["verify_key"] == signer.public_key.hex()
    assert verify_bundle(signed) == (True, "")


def test_hex_and_signer_paths_are_equivalent():
    from perathos.signing import generate_keypair
    sk_hex, vk_hex = generate_keypair()
    via_hex = sign_bundle(create_bundle("x"), sk_hex)
    via_signer = sign_bundle(create_bundle("x"), LocalSigner.from_hex(sk_hex))
    assert via_hex["provider_signature"]["verify_key"] == vk_hex
    assert via_signer["provider_signature"]["verify_key"] == vk_hex
    assert verify_bundle(via_signer) == (True, "")


def test_kms_signer_private_key_never_materialized():
    # Simulate a KMS: the private key lives only inside sign_fn's closure.
    _sk = nacl.signing.SigningKey.generate()
    pub = bytes(_sk.verify_key)
    kms = KmsSigner(key_id=kid_for(pub), public_key=pub, sign_fn=lambda m: _sk.sign(m).signature)
    signed = sign_bundle(create_bundle("kms output"), kms)
    # Identical shape to a local signature, and verifies the same way.
    assert set(signed["provider_signature"]) == {"algorithm", "verify_key", "signature"}
    assert verify_bundle(signed) == (True, "")


def test_trust_store_accepts_trusted_rejects_untrusted():
    signer = LocalSigner.generate()
    signed = sign_bundle(create_bundle("x"), signer)

    trusted = TrustStore().add_signer(signer)
    assert verify_bundle(signed, trust_store=trusted) == (True, "")

    other = TrustStore().add_signer(LocalSigner.generate())
    valid, err = verify_bundle(signed, trust_store=other)
    assert valid is False
    assert err == "ERR_UNTRUSTED_SIGNER"


def test_trust_store_jwks_roundtrip():
    signer = LocalSigner.generate()
    signed = sign_bundle(create_bundle("x"), signer)
    jwks = TrustStore().add_signer(signer).to_jwks()
    assert jwks["keys"][0]["kty"] == "OKP"
    restored = TrustStore.from_jwks(jwks)
    assert verify_bundle(signed, trust_store=restored) == (True, "")
    assert restored.trusts(signer.public_key)


def test_trust_store_rejects_kid_collision():
    ts = TrustStore().add_public_key(bytes(nacl.signing.SigningKey.generate().verify_key))
    kid = next(iter(ts.to_jwks()["keys"]))["kid"]
    try:
        ts.add(kid, b"\x00" * 32)  # same kid, different key
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_kid_is_stable_and_derived():
    pub = bytes(nacl.signing.SigningKey.generate().verify_key)
    assert kid_for(pub) == kid_for(pub)
    assert kid_for(pub).startswith("ed25519-")
