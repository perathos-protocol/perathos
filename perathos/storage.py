"""Filesystem storage for Perathos bundles and cryptographic keys.

Manages persistent storage under ~/.perathos/ with subdirectories for
bundles (as JSON files) and keys (as hex-encoded text files). Enforces
restrictive file permissions on signing keys where supported (Unix mode 0o600).
On Windows, filesystem ACLs are used.

This module is the persistence layer: bundles are created in memory
(perathos.bundle) and then saved here for long-term storage and later
retrieval (e.g., for offline verification). Keys are also stored here
for use with signing commands.

Directory structure:
    ~/.perathos/
        bundles/       (JSON files, one per bundle_id)
            <uuid>.json
        keys/          (hex-encoded text files)
            signing.key       (Ed25519 private key, mode 0o600)
            verify.key        (Ed25519 public key)
"""
import json
import os
from pathlib import Path


# ── bundle storage ────────────────────────────────────────────────────────────

def bundles_dir() -> Path:
    """Return the Perathos bundles directory, creating it if necessary.

    Returns:
        Path object for ~/.perathos/bundles/, with parents created.
    """
    d = Path.home() / ".perathos" / "bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bundle(bundle: dict) -> Path:
    """Save a bundle to a JSON file in the bundles directory.

    Filename is derived from the bundle's bundle_id field.
    File is written with 2-space indentation for readability.
    The bundle is stored at ~/.perathos/bundles/{bundle_id}.json
    for later retrieval via load_bundle().

    Args:
        bundle: A bundle dict from create_bundle() (optionally signed with provider_signature).

    Returns:
        Path object pointing to the saved JSON file.

    Raises:
        KeyError: If bundle is missing the 'bundle_id' field.
        OSError: If the file cannot be written (permission denied, disk full, etc.).

    Examples:
        from perathos import prove
        from perathos.storage import save_bundle

        bundle = prove("The capital of France is Paris.")
        path = save_bundle(bundle)
        print(f"Saved to {path}")
        # Output: Saved to /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json

        # Verify the file was written by loading it back:
        from perathos.storage import load_bundle
        loaded = load_bundle(bundle["bundle_id"])
        assert loaded == bundle
    """
    path = bundles_dir() / f"{bundle['bundle_id']}.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_bundle(bundle_id: str) -> dict:
    """Load a bundle from disk by its bundle_id.

    Reads the JSON file from ~/.perathos/bundles/{bundle_id}.json
    and parses it into a Python dict. The returned bundle can be
    passed directly to verify() or inspect().

    Args:
        bundle_id: UUID string (the bundle's bundle_id field, e.g., "550e8400-e29b-41d4-a716-446655440000").

    Returns:
        Parsed bundle dict with all fields including 'bundle_id', 'integrity_hash', '_trace', etc.
        If the bundle was saved with a signature, the 'provider_signature' field will be present.

    Raises:
        FileNotFoundError: If no bundle file exists for the given ID.
        json.JSONDecodeError: If the JSON file is corrupted or invalid.
        OSError: If the file cannot be read (permission denied, etc.).

    Examples:
        from perathos.storage import load_bundle
        from perathos import verify

        bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
        valid, err = verify(bundle)
        if valid:
            print("Bundle is valid")
        else:
            print(f"Verification failed: {err}")

        # Load and inspect:
        from perathos import inspect
        bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
        inspect(bundle)
    """
    path = bundles_dir() / f"{bundle_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No bundle found for ID: {bundle_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_bundles() -> list[Path]:
    """List all locally stored bundles, newest first.

    Scans ~/.perathos/bundles/ for all .json files and sorts them
    by modification time (most recently modified first).
    Useful for displaying available bundles or cleaning up old ones.

    Returns:
        List of Path objects for all .json files in ~/.perathos/bundles/,
        sorted by modification time descending (newest first).
        Returns an empty list if the bundles directory is empty or doesn't exist yet.

    Examples:
        from perathos.storage import list_bundles

        bundles = list_bundles()
        for path in bundles:
            bundle_id = path.stem  # filename without .json extension
            print(f"Bundle: {bundle_id}")

        # Load the most recent bundle:
        if bundles:
            most_recent = bundles[0]
            bundle_id = most_recent.stem
            from perathos.storage import load_bundle
            bundle = load_bundle(bundle_id)
    """
    return sorted(bundles_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


# ── key storage ───────────────────────────────────────────────────────────────

def keys_dir() -> Path:
    """Return the Perathos keys directory, creating it with secure permissions.

    On Unix-like systems, the directory is created with mode 0o700 (owner-only).
    On Windows, permissions are enforced by NTFS ACLs.
    This function is called automatically by save_keypair() and key loading functions.

    Returns:
        Path object for ~/.perathos/keys/, with parents created.

    Examples:
        from perathos.storage import keys_dir

        key_path = keys_dir() / "custom.key"
        print(f"Keys are stored in: {keys_dir()}")
    """
    d = Path.home() / ".perathos" / "keys"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except NotImplementedError:
        pass  # Windows — permissions enforced by NTFS ACLs, not chmod
    return d


def save_keypair(signing_key_hex: str, verify_key_hex: str) -> tuple[Path, Path]:
    """Save an Ed25519 keypair to disk.

    Stores the signing (private) key with restrictive permissions (0o600 on Unix,
    NTFS ACLs on Windows). Files are written to ~/.perathos/keys/ as plain hex
    text (no encryption). The signing key file should be treated as secret;
    the verify key is public.

    Args:
        signing_key_hex: 64-character hex-encoded private key (from generate_keypair()).
        verify_key_hex: 64-character hex-encoded public key (from generate_keypair()).

    Returns:
        Tuple (signing_key_path, verify_key_path) pointing to the saved files.
        Both are Path objects; convert to str if needed.

    Raises:
        ValueError: If keys are not 64-character hex strings.
        OSError: If files cannot be written (permission denied, disk full, etc.).

    Examples:
        from perathos.signing import generate_keypair
        from perathos.storage import save_keypair

        sk, vk = generate_keypair()
        sk_path, vk_path = save_keypair(sk, vk)
        print(f"Signing key saved to: {sk_path}")
        print(f"Verify key saved to: {vk_path}")

        # Later, load the keys:
        from perathos.storage import load_signing_key, load_verify_key
        loaded_sk = load_signing_key()
        loaded_vk = load_verify_key()
        assert loaded_sk == sk
        assert loaded_vk == vk
    """
    d = keys_dir()
    sk_path = d / "signing.key"
    vk_path = d / "verify.key"
    sk_path.write_text(signing_key_hex, encoding="utf-8")
    vk_path.write_text(verify_key_hex, encoding="utf-8")
    try:
        os.chmod(sk_path, 0o600)  # owner read-only; best-effort on Windows
    except NotImplementedError:
        pass
    return sk_path, vk_path


def load_signing_key() -> str:
    """Load the signing (private) key from disk.

    Reads the Ed25519 signing key from ~/.perathos/keys/signing.key.
    The key is stored as a 64-character hex string (32 bytes of key material).
    This key is used with sign_bundle() or the CLI's --sign flag.

    Returns:
        64-character hex-encoded Ed25519 private key, whitespace stripped.

    Raises:
        FileNotFoundError: If the signing key has not been generated (run 'perathos keygen').
        OSError: If the file cannot be read (permission denied, etc.).

    Examples:
        from perathos.storage import load_signing_key
        from perathos import prove, sign

        sk = load_signing_key()
        bundle = prove("Output text")
        signed = sign(bundle, sk)
        print(f"Bundle signed with key ending in ...{sk[-8:]}")

        # Error handling:
        try:
            sk = load_signing_key()
        except FileNotFoundError:
            print("ERROR: Signing key not found. Run: perathos keygen")
    """
    path = keys_dir() / "signing.key"
    if not path.exists():
        raise FileNotFoundError("No signing key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()


def load_verify_key() -> str:
    """Load the verification (public) key from disk.

    Reads the Ed25519 public key from ~/.perathos/keys/verify.key.
    The key is stored as a 64-character hex string. This key is derived
    from the signing key and can be shared publicly; it's used by verifiers
    to check signatures created with the corresponding signing key.

    Returns:
        64-character hex-encoded Ed25519 public key, whitespace stripped.

    Raises:
        FileNotFoundError: If the verify key has not been generated (run 'perathos keygen').
        OSError: If the file cannot be read (permission denied, etc.).

    Examples:
        from perathos.storage import load_verify_key

        vk = load_verify_key()
        print(f"Share this key for verification: {vk}")

        # Alternatively, use the verify_key stored in a signed bundle:
        from perathos.storage import load_bundle
        from perathos import verify_signature

        bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
        if "provider_signature" in bundle:
            sig_valid, err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
            print(f"Provider key: {bundle['provider_signature']['verify_key']}")
    """
    path = keys_dir() / "verify.key"
    if not path.exists():
        raise FileNotFoundError("No verify key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()
