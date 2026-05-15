"""Filesystem storage for Perathos bundles and cryptographic keys.

Manages persistent storage under ~/.perathos/ with subdirectories for
bundles (as JSON files) and keys (as hex-encoded text files). Enforces
restrictive file permissions on signing keys where supported.
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

    Example usage:
        from perathos import prove
        from perathos.storage import save_bundle

        bundle = prove("The capital of France is Paris.")
        path = save_bundle(bundle)
        print(f"Saved to {path}")
        # Output: Saved to /home/user/.perathos/bundles/<bundle_id>.json

    Args:
        bundle: A bundle dict from create_bundle() (optionally signed).

    Returns:
        Path object pointing to the saved JSON file.
    """
    path = bundles_dir() / f"{bundle['bundle_id']}.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_bundle(bundle_id: str) -> dict:
    """Load a bundle from disk by its bundle_id.

    Example usage:
        from perathos.storage import load_bundle
        from perathos import verify

        bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
        valid, err = verify(bundle)
        if valid:
            print("Bundle is valid")
        else:
            print(f"Verification failed: {err}")

    Args:
        bundle_id: UUID string (the bundle's bundle_id field).

    Returns:
        Parsed bundle dict loaded from ~/.perathos/bundles/{bundle_id}.json.

    Raises:
        FileNotFoundError: If no bundle file exists for the given ID.
    """
    path = bundles_dir() / f"{bundle_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No bundle found for ID: {bundle_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_bundles() -> list[Path]:
    """List all locally stored bundles, newest first.

    Returns:
        List of Path objects for all .json files in ~/.perathos/bundles/,
        sorted by modification time descending (newest first).
    """
    return sorted(bundles_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


# ── key storage ───────────────────────────────────────────────────────────────

def keys_dir() -> Path:
    """Return the Perathos keys directory, creating it with secure permissions.

    On Unix-like systems, the directory is created with mode 0o700 (owner-only).
    On Windows, permissions are enforced by NTFS ACLs.

    Returns:
        Path object for ~/.perathos/keys/, with parents created.
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

    Stores the signing key with restrictive permissions (0o600 on Unix).
    Files are written to ~/.perathos/keys/ as plain hex text.

    Args:
        signing_key_hex: 64-character hex-encoded private key.
        verify_key_hex: 64-character hex-encoded public key.

    Returns:
        Tuple (signing_key_path, verify_key_path) pointing to the saved files.
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
    """Load the signing key from disk.

    Returns:
        64-character hex-encoded Ed25519 signing key from ~/.perathos/keys/signing.key.

    Raises:
        FileNotFoundError: If the signing key has not been generated.
    """
    path = keys_dir() / "signing.key"
    if not path.exists():
        raise FileNotFoundError("No signing key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()


def load_verify_key() -> str:
    """Load the verification (public) key from disk.

    Returns:
        64-character hex-encoded Ed25519 public key from ~/.perathos/keys/verify.key.

    Raises:
        FileNotFoundError: If the verify key has not been generated.
    """
    path = keys_dir() / "verify.key"
    if not path.exists():
        raise FileNotFoundError("No verify key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()
