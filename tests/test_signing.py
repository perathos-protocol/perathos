import hashlib


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


def test_sign_hash_rejects_short_integrity_hash():
    sk, _ = generate_keypair()
    try:
        sign_hash("abc123", sk)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "integrity_hash" in str(exc)
        assert "64" in str(exc)


def test_sign_hash_rejects_long_integrity_hash():
    sk, _ = generate_keypair()
    long_hash = "a" * 128
    try:
        sign_hash(long_hash, sk)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "integrity_hash" in str(exc)
        assert "64" in str(exc)


def test_sign_hash_rejects_invalid_hex_integrity_hash():
    sk, _ = generate_keypair()
    invalid_hash = "z" * 64
    try:
        sign_hash(invalid_hash, sk)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "integrity_hash" in str(exc)
        assert "hex" in str(exc)


def test_sign_hash_rejects_short_signing_key():
    h = _sample_hash()
    try:
        sign_hash(h, "abc123")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "64" in str(exc)


def test_sign_hash_rejects_long_signing_key():
    h = _sample_hash()
    long_key = "a" * 128
    try:
        sign_hash(h, long_key)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "64" in str(exc)


def test_sign_hash_rejects_invalid_hex_signing_key():
    h = _sample_hash()
    invalid_key = "z" * 64
    try:
        sign_hash(h, invalid_key)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "signing_key_hex" in str(exc)
        assert "hex" in str(exc)


def test_verify_signature_rejects_short_integrity_hash():
    sk, vk = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    valid, err = verify_signature("abc123", sig)
    assert valid is False
    assert "ERR_INVALID_HASH" in err


def test_verify_signature_rejects_long_integrity_hash():
    sk, vk = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    valid, err = verify_signature("a" * 128, sig)
    assert valid is False
    assert "ERR_INVALID_HASH" in err


def test_verify_signature_rejects_invalid_hex_integrity_hash():
    sk, vk = generate_keypair()
    h = _sample_hash()
    sig = sign_hash(h, sk)
    valid, err = verify_signature("z" * 64, sig)
    assert valid is False
    assert "ERR_INVALID_HASH" in err


def test_verify_signature_rejects_short_verify_key():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "abc123",
        "signature": "a" * 128,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_VERIFY_KEY" in err


def test_verify_signature_rejects_long_verify_key():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "a" * 128,
        "signature": "a" * 128,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_VERIFY_KEY" in err


def test_verify_signature_rejects_invalid_hex_verify_key():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "z" * 64,
        "signature": "a" * 128,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_VERIFY_KEY" in err


def test_verify_signature_rejects_short_signature():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "a" * 64,
        "signature": "a" * 64,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_SIGNATURE" in err


def test_verify_signature_rejects_long_signature():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "a" * 64,
        "signature": "a" * 256,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_SIGNATURE" in err


def test_verify_signature_rejects_invalid_hex_signature():
    h = _sample_hash()
    sig = {
        "algorithm": "ed25519",
        "verify_key": "a" * 64,
        "signature": "z" * 128,
    }
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_SIGNATURE" in err
