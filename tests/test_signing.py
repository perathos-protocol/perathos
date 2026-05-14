import hashlib

import pytest

from perathos.signing import generate_keypair, sign_hash, verify_signature


def _sample_hash() -> str:
    return hashlib.sha256(b"test payload").hexdigest()


def test_generate_keypair_returns_hex_strings():
    sk, vk = generate_keypair()
    assert len(sk) == 64
    assert len(vk) == 64
    assert all(c in "0123456789abcdef" for c in sk)
    assert all(c in "0123456789abcdef" for c in vk)


def test_sign_and_verify_roundtrip():
    sk, vk = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    assert sig["algorithm"] == "ed25519"
    assert sig["verify_key"] == vk
    valid, err = verify_signature(h, sig)
    assert valid is True
    assert err == ""


def test_verify_rejects_tampered_hash():
    sk, _ = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    tampered = hashlib.sha256(b"different").hexdigest()
    valid, err = verify_signature(tampered, sig)
    assert valid is False
    assert "ERR" in err


def test_verify_rejects_wrong_key():
    sk, _ = generate_keypair()
    _, vk2 = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    sig_wrong_key = {**sig, "verify_key": vk2}
    valid, err = verify_signature(h, sig_wrong_key)
    assert valid is False


def test_verify_missing_field():
    sk, _ = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    del sig["signature"]
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR" in err
