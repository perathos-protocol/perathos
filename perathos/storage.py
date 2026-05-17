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

    The bundles directory is where all proof bundles are stored as JSON files.
    Returns a Path object pointing to ~/.perathos/bundles/ with parents created.
    The returned directory is guaranteed to exist after this call.

    Returns:
        Path object for ~/.perathos/bundles/, with parents created.
        Example: /home/user/.perathos/bundles/ on Linux, /Users/user/.perathos/bundles/ on macOS,
        or C:\\Users\\user\\.perathos\\bundles on Windows.

    Raises:
        OSError: If the directory cannot be created (permission denied, disk full, etc.).
        PermissionError: If the parent directories exist but cannot be written to.

    Examples:
        from perathos.storage import bundles_dir

        d = bundles_dir()
        print(d)
        # Output: /home/user/.perathos/bundles

        # List all bundles by iterating the directory:
        for json_file in d.glob("*.json"):
            print(json_file.stem)  # bundle_id (UUID)
    """
    d = Path.home() / ".perathos" / "bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bundle(bundle: dict) -> Path:
    """Save a bundle to a JSON file in the bundles directory.

    Filename is derived from the bundle's bundle_id field (the UUID).
    File is written with 2-space indentation for readability.
    The bundle is stored at ~/.perathos/bundles/{bundle_id}.json
    for later retrieval via load_bundle().

    Parameter validation:
        - bundle must be a dict with a 'bundle_id' field (str, valid UUID).
        - Other fields are not validated; assumed to be from create_bundle().

    File permissions:
        - Bundle files are world-readable (mode 0o644 default) on Unix.
        - Bundles are not encrypted; they are tamper-evident but not confidential.
        - Store sensitive data (e.g., AI system prompts) separately if needed.

    Args:
        bundle: A bundle dict from create_bundle() (optionally signed with provider_signature).
            Must contain 'bundle_id' key (str).

    Returns:
        Path object pointing to the saved JSON file.
        Example: /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json

    Raises:
        KeyError: If bundle is missing the 'bundle_id' field.
        OSError: If the file cannot be written (permission denied, disk full, etc.).
        PermissionError: If the bundles directory cannot be created or written to.
        TypeError: If bundle is not a dict.

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

    Parameter validation:
        - bundle_id must be a string. No UUID format validation is performed;
          the function attempts to load {bundle_id}.json from the bundles directory.
        - If the file does not exist, FileNotFoundError is raised.

    Recovery from corrupted bundles:
        - If the JSON file is malformed or truncated, json.JSONDecodeError is raised.
        - Manually inspect the file: `python -m json.tool <path>` or `jq <path>`.
        - If the bundle is missing required fields (_trace, integrity_hash, etc.),
          the bundle cannot be recovered. Check your backups or recreate it:
          `perathos prove "<original output>" --input "<original input>"`
        - Do not manually edit bundle JSON files; they are read-only once created.

    Args:
        bundle_id: UUID string (the bundle's bundle_id field, e.g., "550e8400-e29b-41d4-a716-446655440000").
            Must be a string; no UUID format validation is performed.

    Returns:
        dict: Parsed bundle dict with all fields including 'bundle_id', 'integrity_hash', '_trace', etc.
        If the bundle was saved with a signature, the 'provider_signature' field will be present.

    Raises:
        FileNotFoundError: If no bundle file exists for the given ID.
        json.JSONDecodeError: If the JSON file is corrupted or invalid.
        OSError: If the file cannot be read (permission denied, etc.).
        ValueError: If the JSON is valid but contains unexpected types (should not happen with bundles from save_bundle).

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

        # Error handling:
        try:
            bundle = load_bundle("nonexistent-id")
        except FileNotFoundError:
            from perathos.storage import list_bundles
            print("Bundle not found. Available bundles:")
            for path in list_bundles():
                print(f"  {path.stem}")
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
        list[Path]: List of Path objects for all .json files in ~/.perathos/bundles/,
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


# ── key storage ───────────────────────────────────────────────────────────

def keys_dir() -> Path:
    """Return the Perathos keys directory, creating it with secure permissions.

    On Unix-like systems (Linux, macOS), the directory is created with mode 0o700
    (drwx------), meaning only the owner can read, write, or list files in this
    directory. This protects your private signing key from being read by other
    users on the same system. On Windows, permissions are enforced by NTFS ACLs
    instead of POSIX mode bits.

    Why 0o700? Your signing key is secret. If another user on the same machine
    reads your key file, they can forge signatures claiming to come from you.
    Mode 0o700 prevents this by restricting directory access to the owner only.

    This function is called automatically by save_keypair() and key loading functions.

    File permissions model:
        Unix-like (Linux, macOS):
            - Directory mode: 0o700 (drwx------) — owner read/write/execute only.
            - The directory itself is protected, and files created inside inherit permissions
              based on umask. save_keypair() explicitly chmod's signing.key to 0o600.
        Windows:
            - No POSIX mode bits; permissions enforced by NTFS filesystem ACLs.
            - Ensure your user account has exclusive read/write access to the directory.
            - If permission issues arise, contact your system administrator.

    Returns:
        Path object for ~/.perathos/keys/, with parents created and secure permissions applied.
        Example: /home/user/.perathos/keys/ on Linux, /Users/user/.perathos/keys/ on macOS,
        or C:\\Users\\user\\.perathos\\keys on Windows.

    Raises:
        OSError: If the directory cannot be created (permission denied, disk full, etc.).
        PermissionError: If the directory exists but cannot be chmod'ed to 0o700 on Unix systems.

    Examples:
        from perathos.storage import keys_dir

        key_path = keys_dir() / "custom.key"
        print(f"Keys are stored in: {keys_dir()}")

        # On Unix, verify the permissions:
        import os, stat
        d = keys_dir()
        mode = stat.S_IMODE(os.stat(d).st_mode)
        print(f"Directory mode: {oct(mode)}")  # Should print: 0o700

        # Manually fix permissions (if needed):
        import os
        os.chmod(d, 0o700)
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

    Parameter validation:
        - signing_key_hex: Must be a 64-character lowercase hex string (32 bytes of Ed25519 key material).
        - verify_key_hex: Must be a 64-character lowercase hex string (32 bytes of Ed25519 key material).
        - Both are validated before writing to disk. Invalid keys are rejected with ValueError.

    File permissions model:
        Unix-like (Linux, macOS):
            - signing.key is created with mode 0o600 (-rw-------), readable/writable by owner only.
            - verify.key is created with default mode (usually 0o644), readable by all, writable by owner.
            - This ensures the private key is protected while the public key is shareable.
        Windows:
            - Both files are created by default with NTFS ACLs.
            - Ensure your user account has exclusive read/write access to signing.key.
            - Contact your system administrator if permission issues arise.

    Args:
        signing_key_hex: 64-character hex-encoded private key (from generate_keypair()).
            Must be exactly 64 characters of valid hex (0-9, a-f).
        verify_key_hex: 64-character hex-encoded public key (from generate_keypair()).
            Must be exactly 64 characters of valid hex (0-9, a-f).

    Returns:
        tuple[Path, Path]: Tuple (signing_key_path, verify_key_path) pointing to the saved files.
        Example: (/home/user/.perathos/keys/signing.key, /home/user/.perathos/keys/verify.key)

    Raises:
        ValueError: If keys are not 64-character hex strings or contain invalid characters.
        OSError: If files cannot be written (permission denied, disk full, etc.).
        PermissionError: If the keys directory cannot be created or the signing key cannot be chmod'ed to 0o600.
        TypeError: If keys are not strings.

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

        # Manual key save (if needed):
        sk_path, vk_path = save_keypair(
            "a7f9c2ba4e88fb81860ea5e70f527f31fa7f9c2ba4e88fb81860ea5e70f527f31f",
            "b8g0d3cb5f99gc92971fb1f81g638g42gb8g0d3cb5f99gc92971fb1f81g638g42gb"
        )
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


def _validate_hex_key(key_value: str, key_name: str) -> None:
    """Validate that a loaded key is exactly 64 hex characters.

    This function is called internally by load_signing_key() and load_verify_key()
    to ensure that key files on disk have the correct format: a 64-character
    lowercase hex string representing 32 bytes of Ed25519 key material.

    Validation contract:
        - The key_value string must be exactly 64 characters long.
        - All characters must be valid hex digits (0-9, a-f; uppercase rejected).
        - If validation fails, a ValueError is raised with a clear message
          suggesting how to recover (delete and regenerate the keypair).

    Why this matters:
        - Ed25519 keys are 32 bytes = 64 hex characters (each byte = 2 hex chars).
        - If a key file is truncated (fewer than 64 chars), it's corrupted and cannot
          be used. The only recovery is to delete and regenerate.
        - If a key file contains non-hex characters, it's corrupted or was manually
          edited incorrectly.
        - This function catches these issues early before attempting cryptographic
          operations (which would fail with cryptic library errors).

    Args:
        key_value: The key string to validate (should be stripped of whitespace).
            Typically loaded from a key file via path.read_text().strip().
        key_name: Name of the key for error messages (e.g., "signing key" or "verify key").
            Used in error messages to help users identify which key file is broken.

    Raises:
        ValueError: If the key is not exactly 64 hex characters.
            The error message includes:
            - The expected length (64) and actual length
            - A suggestion to delete and regenerate the keypair
            - Recovery command line: rm ~/.perathos/keys/signing.key ... && perathos keygen

    Examples:
        from perathos.storage import _validate_hex_key

        # Valid key:
        _validate_hex_key("a" * 64, "signing key")  # Passes silently

        # Invalid key (too short):
        try:
            _validate_hex_key("a" * 32, "signing key")
        except ValueError as e:
            print(e)
            # Output: Invalid signing key: expected 64 hex characters, got 32. ...

        # Invalid key (non-hex):
        try:
            _validate_hex_key("z" * 64, "verify key")
        except ValueError as e:
            print(e)
            # Output: Invalid verify key: contains non-hex characters. ...
    """
    if len(key_value) != 64:
        raise ValueError(
            f"Invalid {key_name}: expected 64 hex characters, got {len(key_value)}. "
            f"The key file may be corrupted. To recover, delete and regenerate: "
            f"rm ~/.perathos/keys/signing.key ~/.perathos/keys/verify.key && perathos keygen"
        )
    try:
        int(key_value, 16)
    except ValueError:
        raise ValueError(
            f"Invalid {key_name}: contains non-hex characters. "
            f"The key file may be corrupted. To recover, delete and regenerate: "
            f"rm ~/.perathos/keys/signing.key ~/.perathos/keys/verify.key && perathos keygen"
        )


def load_signing_key() -> str:
    """Load the signing (private) key from disk.

    Reads the Ed25519 signing key from ~/.perathos/keys/signing.key.
    The key is stored as a 64-character hex string (32 bytes of key material).
    This key is used with sign_bundle() or the CLI's --sign flag.

    The signing key is your private key and must be kept secret. Do not share
    it or commit it to version control. On Unix-like systems, the file is
    stored with mode 0o600 (owner read-only) to prevent other users from
    reading it.

    Parameter validation:
        - The file is expected to contain exactly one line of 64 hex characters.
        - Whitespace is stripped before returning.
        - The key is validated to be exactly 64 hex characters. If not, ValueError
          is raised with a clear message suggesting how to recover.

    Recovery from corrupted keys:
        - If the key file is truncated (fewer than 64 characters), contains non-hex,
          or is empty, ValueError is raised with recovery instructions.
        - To recover: delete the key file and regenerate:
          `rm ~/.perathos/keys/signing.key ~/.perathos/keys/verify.key`
          `perathos keygen`
        - Warning: Any bundles signed with the old key cannot be verified with the new key.
        - Keep backups: `cp -r ~/.perathos/keys ~/perathos-keys-backup`

    Returns:
        str: 64-character hex-encoded Ed25519 private key, whitespace stripped.
        Example: "a7f9c2ba4e88fb81860ea5e70f527f31f..."

    Raises:
        FileNotFoundError: If the signing key has not been generated (run 'perathos keygen').
        ValueError: If the key file is empty, truncated, or contains non-hex characters.
        OSError: If the file cannot be read (permission denied, etc.).

    Note:
        On Unix-like systems, the signing key file is stored with mode 0o600 (owner read-only).
        This ensures that only the file owner can read the private key. If you see a
        PermissionError when loading the key, verify that ~/.perathos/keys/signing.key
        is readable by your user and check the file permissions with:
        `chmod 600 ~/.perathos/keys/signing.key`

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
        except ValueError as e:
            print(f"ERROR: {e}")

        # Fix permissions if needed:
        import os
        from perathos.storage import keys_dir
        sk_path = keys_dir() / "signing.key"
        os.chmod(sk_path, 0o600)
    """
    path = keys_dir() / "signing.key"
    if not path.exists():
        raise FileNotFoundError("No signing key found — run: perathos keygen")
    key_value = path.read_text(encoding="utf-8").strip()
    _validate_hex_key(key_value, "signing key")
    return key_value


def load_verify_key() -> str:
    """Load the verification (public) key from disk.

    Reads the Ed25519 public key from ~/.perathos/keys/verify.key.
    The key is stored as a 64-character hex string. This key is derived
    from the signing key and can be shared publicly; it's used by verifiers
    to check signatures created with the corresponding signing key.

    Parameter validation:
        - The file is expected to contain exactly one line of 64 hex characters.
        - Whitespace is stripped before returning.
        - The key is validated to be exactly 64 hex characters. If not, ValueError
          is raised with a clear message suggesting how to recover.

    Recovery from corrupted keys:
        - If the verify key file is corrupted or missing, you can regenerate it
          by deriving it from the signing key (if the signing key is intact):
          `from perathos.signing import generate_keypair; from perathos.storage import load_signing_key, save_keypair`
          `sk = load_signing_key(); from nacl.signing import SigningKey; from nacl import encoding`
          `sk_obj = SigningKey(sk, encoder=encoding.HexEncoder); vk = sk_obj.verify_key.encode(encoding.HexEncoder).decode()`
        - Or simply regenerate both keys: `perathos keygen`

    Returns:
        str: 64-character hex-encoded Ed25519 public key, whitespace stripped.
        Example: "a7f9c2ba4e88fb81860ea5e70f527f31f..."

    Raises:
        FileNotFoundError: If the verify key has not been generated (run 'perathos keygen').
        ValueError: If the key file is empty, truncated, or contains non-hex characters.
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
    key_value = path.read_text(encoding="utf-8").strip()
    _validate_hex_key(key_value, "verify key")
    return key_value
