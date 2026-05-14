import json
import os
from pathlib import Path


# ── bundle storage ────────────────────────────────────────────────────────────

def bundles_dir() -> Path:
    d = Path.home() / ".perathos" / "bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bundle(bundle: dict) -> Path:
    path = bundles_dir() / f"{bundle['bundle_id']}.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_bundle(bundle_id: str) -> dict:
    path = bundles_dir() / f"{bundle_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No bundle found for ID: {bundle_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_bundles() -> list[Path]:
    return sorted(bundles_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


# ── key storage ───────────────────────────────────────────────────────────────

def keys_dir() -> Path:
    d = Path.home() / ".perathos" / "keys"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except NotImplementedError:
        pass  # Windows — permissions enforced by NTFS ACLs, not chmod
    return d


def save_keypair(signing_key_hex: str, verify_key_hex: str) -> tuple[Path, Path]:
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
    path = keys_dir() / "signing.key"
    if not path.exists():
        raise FileNotFoundError("No signing key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()


def load_verify_key() -> str:
    path = keys_dir() / "verify.key"
    if not path.exists():
        raise FileNotFoundError("No verify key found — run: perathos keygen")
    return path.read_text(encoding="utf-8").strip()
