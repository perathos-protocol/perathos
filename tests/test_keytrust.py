"""Tests for the KMS-ready signer + TrustStore/JWKS trust anchoring."""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    _sk = Ed25519PrivateKey.generate()
    pub = _sk.public_key().public_bytes_raw()
    kms = KmsSigner(key_id=kid_for(pub), public_key=pub, sign_fn=lambda m: _sk.sign(m))
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
    ts = TrustStore().add_public_key(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    kid = next(iter(ts.to_jwks()["keys"]))["kid"]
    try:
        ts.add(kid, b"\x00" * 32)  # same kid, different key
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_kid_is_stable_and_derived():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert kid_for(pub) == kid_for(pub)
    assert kid_for(pub).startswith("ed25519-")


# ── Adversarial trust-anchor probes (0.2.7) ───────────────────────────────────

def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_from_jwks_rejects_kid_not_matching_key():
    # Defense in depth: a JWKS entry whose kid does not match its key (a tampered
    # or kid-spoofed entry) is rejected at LOAD time, not stored as an inert entry.
    attacker = LocalSigner.generate()
    spoof = {"keys": [{"kty": "OKP", "crv": "Ed25519",
                       "kid": "ed25519-deadbeefdeadbeef", "x": _b64u(attacker.public_key)}]}
    with pytest.raises(ValueError, match="does not match"):
        TrustStore.from_jwks(spoof)


def test_from_jwks_untrusted_key_is_never_accepted():
    # The core invariant: a key the consumer did not trust can't verify, even if
    # the attacker controls the bundle's embedded verify_key.
    legit, attacker = LocalSigner.generate(), LocalSigner.generate()
    trust = TrustStore().add_signer(legit)
    forged = sign_bundle(create_bundle("x", model="m"), attacker)
    assert verify_bundle(forged, trust_store=trust) == (False, "ERR_UNTRUSTED_SIGNER")


@pytest.mark.parametrize("jwks", [
    {"keys": [{"kid": "k1"}]},                       # missing x
    {"keys": [{"x": "AAAA"}]},                        # missing kid
    {"keys": [{"kid": "k1", "x": "@@@@"}]},           # invalid base64url
    {"keys": [{"kid": "k1", "x": 123}]},              # x not a string
    {"keys": "nope"},                                  # keys not a list
    {"keys": [42]},                                    # entry not an object
    "not-an-object",                                   # jwks not an object
    {"keys": [{"kid": "k1", "x": _b64u(b"\x00" * 8)}]},  # wrong key length
])
def test_from_jwks_fails_cleanly_on_malformed_input(jwks):
    # A malformed/hostile JWKS must raise a clear ValueError, never crash with a
    # raw KeyError / TypeError / binascii.Error.
    with pytest.raises(ValueError):
        TrustStore.from_jwks(jwks)
