"""Destructive-action guard: no irreversible command without a signed safety check.

Before a coding agent runs a command that can destroy data (``rm -rf``,
``DROP TABLE``, ``terraform destroy``, deleting a cloud volume or backup...),
the PreToolUse hook asks: is there a *precondition* -- signed by the local
key, unexpired, covering this target -- showing a safety check passed (for
example, a backup was restored and listed successfully)? If not, the call is
denied and the agent is told exactly what a human must do. Either way the
decision is written into the flight-recorder receipt.

A precondition is created by a person, not the agent::

    perathos precondition add --scope prod-db \\
        --check "pg_restore --list backups/prod-latest.dump"

The check command is run; only if it exits 0 is a precondition signed and
saved to ``.perathos/preconditions/``. It records the command, a hash of its
output, who signed it and when it expires (default 30 minutes).

Honest limits:
  * Pattern matching is a seatbelt for accidents (the PocketOS-class "agent
    deletes prod and the backups" incident), not a sandbox against a
    deliberately hostile agent: a command can be obfuscated past any regex.
  * The signing key lives on the same machine. The guard refuses agent
    commands that create preconditions or touch ``.perathos/keys``, but an
    agent with unrestricted shell access could still reach the key some
    other way. Keep the key somewhere the agent cannot read for real
    separation (planned: KMS-backed signer).
  * A precondition proves the check ran and passed. Whether that check is a
    meaningful test of the backup is the person's judgement.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes

PRECONDITION_VERSION = "perathos.precondition/v1"
DEFAULT_TTL_MINUTES = 30


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern
    description: str


def _r(rule_id: str, regex: str, description: str) -> Rule:
    return Rule(rule_id, re.compile(regex, re.IGNORECASE), description)


# Shell / CLI commands that can destroy data or the means to recover it.
SHELL_RULES: tuple[Rule, ...] = (
    _r("fs.rm-recursive",
       r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\b.*--force|--force\b.*--recursive|-r\s+-f|-f\s+-r)\b",
       "recursive forced delete"),
    _r("fs.remove-item-recurse", r"\bremove-item\b.*-recurse", "PowerShell recursive delete"),
    _r("sql.drop", r"\bdrop\s+(database|schema|table)\b", "SQL DROP"),
    _r("sql.truncate", r"\btruncate\s+(table\s+)?[\w.\"`]+", "SQL TRUNCATE"),
    _r("sql.delete-all", r"\bdelete\s+from\s+[\w.\"`]+\s*(;|$|\"|')", "SQL DELETE without WHERE"),
    _r("db.dropdb", r"\bdropdb\b", "PostgreSQL dropdb"),
    _r("db.redis-flush", r"\bflush(all|db)\b", "Redis FLUSHALL / FLUSHDB"),
    _r("db.mongo-drop", r"\.drop(database)?\s*\(", "MongoDB drop"),
    _r("db.migrate-reset", r"\b(prisma\s+migrate\s+reset|rails\s+db:(drop|reset)|supabase\s+db\s+reset|heroku\s+pg:reset)\b",
       "database reset"),
    _r("iac.terraform-destroy", r"\bterraform\s+(destroy|apply\b.*-destroy)\b", "terraform destroy"),
    _r("iac.pulumi-destroy", r"\bpulumi\s+destroy\b", "pulumi destroy"),
    _r("k8s.delete", r"\bkubectl\s+delete\s+(ns|namespace|pv|pvc|persistentvolume\w*|statefulset|deployment|all)\b",
       "kubectl delete of stateful resources"),
    _r("cloud.aws-delete",
       r"\baws\s+(s3\s+rb\b|s3\s+rm\b.*--recursive|rds\s+delete-|dynamodb\s+delete-table|ec2\s+delete-(volume|snapshot)|backup\s+delete-)",
       "AWS delete of storage or backups"),
    _r("cloud.gcloud-delete", r"\bgcloud\s+.*\b(sql\s+instances|compute\s+disks|compute\s+snapshots|storage\s+(buckets\s+)?rm)\b.*\bdelete\b|\bgcloud\s+storage\s+rm\b",
       "Google Cloud delete of storage or backups"),
    _r("cloud.az-delete", r"\baz\s+(sql|storage|disk|snapshot|backup|cosmosdb)\b.*\bdelete\b", "Azure delete of storage or backups"),
    _r("paas.railway", r"\brailway\s+(down|volume\s+delete|delete)\b", "Railway delete"),
    _r("paas.vercel", r"\bvercel\s+(remove|rm)\b", "Vercel remove"),
    _r("paas.fly", r"\bfly(ctl)?\s+(volumes?\s+(destroy|delete)|apps?\s+destroy|postgres\s+destroy)\b", "Fly destroy"),
    _r("paas.neon", r"\bneon(ctl)?\s+(branches?|projects?|databases?)\s+delete\b", "Neon delete"),
    _r("docker.volume", r"\bdocker\s+(volume\s+(rm|prune)|system\s+prune\b.*--volumes)", "Docker volume delete"),
    _r("git.force-push-main", r"\bgit\s+push\b.*(--force\b|-f\b).*\b(main|master|prod|production)\b", "force push to a main branch"),
)

# Self-authorization: the agent must not create its own preconditions or read the key.
SELF_AUTH_RULES: tuple[Rule, ...] = (
    _r("guard.self-authorize", r"\bperathos\s+(precondition|keygen)\b",
       "agent tried to create its own safety precondition or replace the signing key"),
    _r("guard.key-access", r"\.perathos[\\/]+keys\b", "agent tried to access the perathos signing key"),
)

# Non-shell tools (MCP servers etc.) whose *name* says they destroy things.
_DESTRUCTIVE_TOOL_NAME = re.compile(r"(delete|drop|destroy|purge|truncate|wipe|reset|remove)", re.IGNORECASE)
_SHELL_TOOLS = {"Bash", "PowerShell", "bash", "shell"}
_FILE_TOOLS_WITH_PATH = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"}


@dataclass(frozen=True)
class Match:
    rule_id: str
    description: str
    subject: str  # the text that was matched against (command or tool name)
    self_auth: bool = False


def evaluate(tool_name: str, tool_input: Any) -> Match | None:
    """Return the first destructive-action rule a tool call matches, or None."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name in _SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        for rule in SELF_AUTH_RULES:
            if rule.pattern.search(command):
                return Match(rule.rule_id, rule.description, command, self_auth=True)
        for rule in SHELL_RULES:
            if rule.pattern.search(command):
                return Match(rule.rule_id, rule.description, command)
        return None
    if tool_name in _FILE_TOOLS_WITH_PATH:
        target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if SELF_AUTH_RULES[1].pattern.search(target):
            r = SELF_AUTH_RULES[1]
            return Match(r.rule_id, r.description, target, self_auth=True)
        return None
    if tool_name.startswith("mcp__") and _DESTRUCTIVE_TOOL_NAME.search(tool_name.split("__")[-1]):
        subject = tool_name + " " + json.dumps(tool_input, sort_keys=True, default=str)[:500]
        return Match("mcp.destructive-tool", "MCP tool whose name says it destroys data", subject)
    return None


# --------------------------------------------------------------------------- #
# Preconditions
# --------------------------------------------------------------------------- #

def preconditions_dir(cwd: str | os.PathLike) -> Path:
    return Path(cwd) / ".perathos" / "preconditions"


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def precondition_hash(pc: dict) -> str:
    body = {k: v for k, v in pc.items() if k not in ("precondition_hash", "signature")}
    return _sha256(canonical_bytes(body))


def create_precondition(
    cwd: str | os.PathLike,
    *,
    scope: str,
    signing_key_hex: str,
    check: str | None = None,
    manual_reason: str | None = None,
    ttl_minutes: int = DEFAULT_TTL_MINUTES,
    timeout: float = 600.0,
) -> tuple[dict | None, dict]:
    """Run the check (if any) and, only if it passes, write a signed precondition.

    Returns (precondition or None, check_result). ``check_result`` has
    ``exit_code`` and ``output`` (combined stdout/stderr) for display.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .signing import sign_hash

    if not scope.strip():
        raise ValueError("scope must not be empty (use '*' to cover every target)")
    if (check is None) == (manual_reason is None):
        raise ValueError("give exactly one of --check (a command to run) or --manual (a reason)")

    result: dict[str, Any] = {"exit_code": None, "output": ""}
    if check is not None:
        proc = subprocess.run(check, shell=True, cwd=str(cwd), capture_output=True, timeout=timeout)  # noqa: S602 - run by a person on purpose
        output = proc.stdout + proc.stderr
        result = {"exit_code": proc.returncode, "output": output.decode("utf-8", errors="replace")}
        if proc.returncode != 0:
            return None, result

    now = datetime.now(timezone.utc)
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
    pc: dict[str, Any] = {
        "v": PRECONDITION_VERSION,
        "id": str(uuid.uuid4()),
        "kind": "safety-check",
        "scope": scope,
        "check": check,
        "check_exit_code": result["exit_code"],
        "check_output_hash": _sha256(result["output"].encode("utf-8")) if check is not None else None,
        "manual_reason": manual_reason,
        "created": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires": (now + timedelta(minutes=ttl_minutes)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "signer": sk.public_key().public_bytes_raw().hex(),
    }
    pc["precondition_hash"] = precondition_hash(pc)
    pc["signature"] = sign_hash(pc["precondition_hash"], signing_key_hex)
    d = preconditions_dir(cwd)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{pc['id']}.json").write_text(json.dumps(pc, indent=2, sort_keys=True), encoding="utf-8")
    return pc, result


def check_precondition(pc: dict, *, trusted_key: str, now: datetime | None = None) -> str | None:
    """Return None if the precondition is valid now, else a short reason."""
    from .signing import verify_signature

    if pc.get("v") != PRECONDITION_VERSION:
        return "unknown precondition version"
    try:
        if precondition_hash(pc) != pc.get("precondition_hash"):
            return "precondition was modified"
    except (TypeError, ValueError):
        return "malformed precondition"
    sig = pc.get("signature")
    if not isinstance(sig, dict):
        return "precondition is unsigned"
    ok, _ = verify_signature(str(pc.get("precondition_hash")), sig)
    if not ok:
        return "precondition signature is invalid"
    if sig.get("verify_key") != trusted_key or pc.get("signer") != trusted_key:
        return "precondition was signed by an untrusted key"
    now = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(str(pc.get("expires")).replace("Z", "+00:00"))
    except ValueError:
        return "malformed expiry"
    if now >= expires:
        return "precondition has expired"
    return None


def _covers(scope: str, subject: str) -> bool:
    return scope == "*" or scope.lower() in subject.lower()


def find_precondition(cwd: str | os.PathLike, subject: str, *, trusted_key: str) -> dict | None:
    """The newest valid precondition whose scope covers this command, if any."""
    d = preconditions_dir(cwd)
    if not d.exists():
        return None
    best = None
    for f in d.glob("*.json"):
        try:
            pc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(pc, dict) or not _covers(str(pc.get("scope", "")), subject):
            continue
        if check_precondition(pc, trusted_key=trusted_key) is None:
            if best is None or str(pc.get("created")) > str(best.get("created")):
                best = pc
    return best


@dataclass
class Decision:
    decision: str  # "allow" | "deny"
    rule: str | None = None
    precondition: str | None = None  # precondition_hash used
    reason: str = ""

    def receipt_field(self) -> dict:
        return {"decision": self.decision, "rule": self.rule, "precondition": self.precondition}


def decide(tool_name: str, tool_input: Any, cwd: str | os.PathLike, *, trusted_key: str | None) -> Decision | None:
    """Guard decision for one tool call; None when no rule matches."""
    m = evaluate(tool_name, tool_input)
    if m is None:
        return None
    if m.self_auth:
        return Decision("deny", m.rule_id, None,
                        f"perathos guard: blocked ({m.description}). Preconditions must be created by a "
                        f"person outside the agent session.")
    hint = ('A person must first run, outside this agent session:\n'
            '  perathos precondition add --scope "<target name in the command>" --check "<command that '
            'proves a restorable backup exists>"\n'
            'then retry. The check must exit 0.')
    if trusted_key is None:
        return Decision("deny", m.rule_id, None,
                        f"perathos guard: blocked {m.description}. No signing key exists, so no safety "
                        f"precondition can be trusted. Run 'perathos keygen', then:\n{hint}")
    pc = find_precondition(cwd, m.subject, trusted_key=trusted_key)
    if pc is None:
        return Decision("deny", m.rule_id, None,
                        f"perathos guard: blocked {m.description} ({m.rule_id}). No unexpired, signed safety "
                        f"precondition covers this command.\n{hint}")
    return Decision("allow", m.rule_id, pc["precondition_hash"],
                    f"perathos guard: allowed {m.description} under precondition {pc['id']} "
                    f"(scope {pc['scope']!r}, expires {pc['expires']})")
