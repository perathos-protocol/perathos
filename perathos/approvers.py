"""Approvers: the people whose keys may sign safety preconditions.

By default the guard trusts preconditions signed by the local recorder key, so
one key on one machine both seals the log and approves destructive actions. That
is convenient, and weak: an agent that ever reads that key can approve itself.

Adding approvers separates the two. Once ``~/.perathos/approvers.json`` lists at
least one approver, the guard trusts *only* preconditions signed by a listed
key, and the recorder key is no longer an approver unless it is listed too.
Approver keys can live off the machine (``perathos precondition add --signer
vault:... | gcpkms:... | command:...``), so the agent never has them.

``~/.perathos/config.json`` holds small settings shared by the CLI and hooks:
``signer`` (recorder signer spec) and ``anchor_mirror`` (a folder that receives
a copy of every timestamp). Both files live under ``.perathos/``, which the
guard refuses to let the agent write.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

CONFIG_KEYS = ("signer", "anchor_mirror")


def perathos_home() -> Path:
    return Path.home() / ".perathos"


def approvers_path() -> Path:
    return Path(os.environ.get("PERATHOS_APPROVERS") or perathos_home() / "approvers.json")


def config_path() -> Path:
    return perathos_home() / "config.json"


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def get_config() -> dict:
    return _read_json(config_path())


def set_config(key: str, value: str | None) -> dict:
    if key not in CONFIG_KEYS:
        raise ValueError(f"unknown setting {key!r}; known: {', '.join(CONFIG_KEYS)}")
    cfg = get_config()
    if value is None:
        cfg.pop(key, None)
    else:
        cfg[key] = value
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
    return cfg


def list_approvers() -> list[dict]:
    items = _read_json(approvers_path()).get("approvers")
    return [a for a in items if isinstance(a, dict) and isinstance(a.get("verify_key"), str)] if isinstance(items, list) else []


def _valid_key(hex_key: str) -> bool:
    return len(hex_key) == 64 and all(c in "0123456789abcdef" for c in hex_key)


def add_approver(name: str, verify_key: str) -> list[dict]:
    verify_key = verify_key.strip().lower()
    if not _valid_key(verify_key):
        raise ValueError("approver key must be a 64-character hex Ed25519 public key")
    if not name.strip():
        raise ValueError("approver name must not be empty")
    items = [a for a in list_approvers() if a.get("name") != name and a.get("verify_key") != verify_key]
    items.append({"name": name, "verify_key": verify_key,
                  "added": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")})
    approvers_path().parent.mkdir(parents=True, exist_ok=True)
    approvers_path().write_text(json.dumps({"approvers": items}, indent=2), encoding="utf-8")
    return items


def remove_approver(name_or_key: str) -> list[dict]:
    items = [a for a in list_approvers() if name_or_key not in (a.get("name"), a.get("verify_key"))]
    approvers_path().write_text(json.dumps({"approvers": items}, indent=2), encoding="utf-8")
    return items


def local_verify_key() -> str | None:
    try:
        vk = (perathos_home() / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return vk if _valid_key(vk) else None


def trusted_approver_keys() -> set[str] | None:
    """Keys whose preconditions the guard accepts; None if there are none at all."""
    listed = {a["verify_key"] for a in list_approvers() if _valid_key(a["verify_key"])}
    if listed:
        return listed
    vk = local_verify_key()
    return {vk} if vk else None


def approver_name(verify_key: str) -> str | None:
    for a in list_approvers():
        if a.get("verify_key") == verify_key:
            return a.get("name")
    return None
