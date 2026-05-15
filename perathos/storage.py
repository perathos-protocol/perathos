import json
import os
from pathlib import Path


# ── bundle storage ────────────────────────────────────────────────────────────

def bundles_dir() -> Path:
    """Return the bundles directory, creating it if necessary."""
    d = Path.home() / ".perathos" / "bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bundle(bundle: dict) -> Path:
    """Save a bundle to ~/.perathos/bundles/{bundle_id}.json."""
    path = bundles_dir() / f"{bundle['bundle_id']}.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_bundle(bundle_id: str) -> dict:
    """Load a bundle from ~/.perathos/bundles/{bundle_id}.json.

    Raises FileNotFoundError if the bundle does not exist.
    Raises ValueError if the JSON is malformed.
    """
    path = bundles_dir() / f"{bundle_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No bundle found for ID: {bundle_id}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in bundle {bundle_id}: {exc}") from exc


def list_bundles() -> list[Path]:
    """List all stored bundles, sorted by modification time (newest first)."""
    return sorted(bundles_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


# ── key storage ───────────────────────────────────────────────────────────────

def keys_dir() -> Path:
    """Return the keys directory, creating it if necessary.

    Attempts to restrict permissions to owner-only (0o700) on Unix-like systems.
    Gracefully degrades on systems that don't support chmod or have permission failures.
    """
    d = Path.home() / ".perathos" / "keys"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(f"Failed to create keys directory {d}: {exc}") from exc
    try:
        os.chmod(d, 0o700)
    except (NotImplementedError, OSError):
        # NotImplementedError: Windows (permissions via NTFS ACLs)
        # OSError: Permission denied or other system-level failures
        pass
    return d


def save_keypair(signing_key_hex: str, verify_key_hex: str) -> tuple[Path, Path]:
    """Save a keypair to ~/.perathos/keys/signing.key and verify.key.

    Raises OSError if unable to create or write to the keys directory.
    """
    d = keys_dir()
    sk_path = d / "signing.key"
    vk_path = d / "verify.key"
    try:
        sk_path.write_text(signing_key_hex, encoding="utf-8")
        vk_path.write_text(verify_key_hex, encoding="utf-8")
    except (OSError, IOError) as exc:
        raise OSError(f"Failed to write keypair to {d}: {exc}") from exc
    try:
        os.chmod(sk_path, 0o600)  # owner read-only; best-effort on Windows
    except (NotImplementedError, OSError):
        pass
    return sk_path, vk_path


def load_signing_key() -> str:
    """Load the signing key from ~/.perathos/keys/signing.key.

    Raises FileNotFoundError if the key does not exist.
    """
    path = keys_dir() / "signing.key"
    if not path.exists():
        raise FileNotFoundError("No signing key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()


def load_verify_key() -> str:
    """Load the verify key from ~/.perathos/keys/verify.key.

    Raises FileNotFoundError if the key does not exist.
    """
    path = keys_dir() / "verify.key"
    if not path.exists():
        raise FileNotFoundError("No verify key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()
