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
# Matched against a normalised copy of the command (quotes removed, SQL
# comments collapsed), so `r""m -rf`, `k''eys` and `DROP/**/TABLE` match.
SHELL_RULES: tuple[Rule, ...] = (
    _r("fs.rm-recursive",
       r"\brm\s+(-\S+\s+)*(-[a-z]*r|--recursive\b)|\brm\s+(-\S+\s+)*-[a-z]*f[a-z]*r",
       "recursive delete"),
    _r("fs.win-delete",
       r"(^|[\s;&|(])(del|erase)\s+(/\w\s+)*/[sq]\b|(^|[\s;&|(])(rd|rmdir)\s+(/\w\s+)*/s\b|(^|[\s;&|(])format\s+[a-z]:",
       "Windows recursive or quiet delete"),
    _r("fs.ps-delete",
       r"\b(remove-item|ri|del|erase|rd|rmdir|rm)\s+(\S+\s+)*-(r|recurse|rec|force)\b",
       "PowerShell recursive delete"),
    _r("fs.find-delete", r"\bfind\b.*\s(-delete\b|-exec\s+rm\b)", "find -delete"),
    _r("fs.truncate-or-overwrite",
       r"\btruncate\s+(-s\s*0|--size[= ]0)\b|\bdd\s+.*\bof=(?!/dev/null)|\bshred\b|\bmv\s+\S+\s+/dev/null|(^|[;&|])\s*:\s*>\s*\S",
       "file truncated, overwritten or shredded"),
    _r("fs.interpreter-delete",
       r"shutil\.rmtree|\.(rm|rmSync|rmdir|rmdirSync|promises\.rm)\s*\(.*recursive|\brimraf\b|FileUtils\.rm_rf|\bos\.(remove|unlink|rmdir|removedirs)\s*\(.*\*",
       "delete through an interpreter one-liner"),
    _r("git.destructive",
       r"\bgit\s+(reset\s+--hard|clean\s+-\S*[fd]|checkout\s+(--\s|\.\s*$|\.\s)|restore\s+(--staged\s+)?(\.|--\s)|branch\s+(?-i:-D)\b|stash\s+(drop|clear)|filter-branch|reflog\s+expire|update-ref\s+-d)",
       "git command that discards work"),
    _r("git.force-push-main", r"\bgit\s+push\b.*(--force\b|-f\b|--mirror\b).*\b(main|master|prod|production)\b|\bgit\s+push\s+--mirror\b",
       "force push to a main branch"),
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
       r"\baws\s+(s3\s+rb\b|s3\s+rm\b.*--recursive|s3\s+rm\s+--recursive|rds\s+delete-|dynamodb\s+delete-table|ec2\s+delete-(volume|snapshot)|backup\s+delete-)",
       "AWS delete of storage or backups"),
    _r("cloud.gcloud-delete", r"\bgcloud\s+.*\b(sql\s+instances|compute\s+disks|compute\s+snapshots|storage\s+(buckets\s+)?rm)\b.*\bdelete\b|\bgcloud\s+storage\s+rm\b",
       "Google Cloud delete of storage or backups"),
    _r("cloud.az-delete", r"\baz\s+(sql|storage|disk|snapshot|backup|cosmosdb)\b.*\bdelete\b", "Azure delete of storage or backups"),
    _r("paas.railway", r"\brailway\s+(down|volume\s+delete|delete)\b", "Railway delete"),
    _r("paas.vercel", r"\bvercel\s+(remove|rm)\b", "Vercel remove"),
    _r("paas.fly", r"\bfly(ctl)?\s+(volumes?\s+(destroy|delete)|apps?\s+destroy|postgres\s+destroy)\b", "Fly destroy"),
    _r("paas.neon", r"\bneon(ctl)?\s+(branches?|projects?|databases?)\s+delete\b", "Neon delete"),
    _r("docker.volume", r"\bdocker\s+(volume\s+(rm|prune)|system\s+prune\b.*--volumes)", "Docker volume delete"),
)

# Self-authorization and self-disabling: the agent must not create its own
# preconditions, touch the signing key, or change the files that keep the
# recorder and guard running.
_ENFORCEMENT_PATHS = r"(\.perathos[\\/]|\.claude[\\/]+settings|\.cursor[\\/]+hooks|managed-settings|claudecode[\\/]+managed)"
SELF_AUTH_RULES: tuple[Rule, ...] = (
    _r("guard.self-authorize", r"\bperathos\s+(precondition|keygen)\b",
       "agent tried to create its own safety precondition or replace the signing key"),
    _r("guard.key-access", r"\.perathos[\\/]+keys\b|signing\.key\b", "agent tried to access the perathos signing key"),
    _r("guard.self-disable", _ENFORCEMENT_PATHS,
       "agent tried to change the files that keep the recorder and guard running"),
)
# Reading those files is fine; only commands that could write them are denied.
_READ_ONLY_PREFIX = re.compile(r"^\s*(cat|type|ls|dir|head|tail|less|more|stat|get-content|gc|get-childitem|perathos|git\s+(status|diff|log|show))\b", re.I)

# Non-shell tools (MCP servers etc.) whose *name* says they destroy things.
_DESTRUCTIVE_TOOL_NAME = re.compile(r"(delete|drop|destroy|purge|truncate|wipe|reset|remove)", re.IGNORECASE)
_SHELL_TOOLS = {"Bash", "PowerShell", "bash", "shell"}
_FILE_TOOLS_WITH_PATH = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".sql", ".rb", ".pl")
# `bash x.sh`, `python x.py`, `psql -f x.sql`, `./x.sh`: scripts the command runs
_SCRIPT_RUN = re.compile(
    r"(?:^|[\s;&|(])(?:\.?/|bash\s+|sh\s+|zsh\s+|source\s+|\.\s+|python3?\s+|node\s+|pwsh\s+(?:-\S+\s+)*|powershell\s+(?:-\S+\s+)*|psql\b.*?\s-f\s+|mysql\b.*?<\s*|sqlite3\b.*?<\s*)"
    r"([^\s;&|)<>\"']+)", re.I)
_MAX_SCRIPT_BYTES = 1 << 20
_CMD_NORMALISERS = (
    (re.compile(r"""['"`]"""), ""),            # r""m -rf, k''eys
    (re.compile(r"\\\r?\n"), " "),             # line continuations
    (re.compile(r"/\*.*?\*/", re.S), " "),     # SQL block comments
    (re.compile(r"[ \t]+"), " "),
)


def normalize_command(command: str) -> str:
    """The text rules are matched against: quotes stripped, comments collapsed."""
    for rx, rep in _CMD_NORMALISERS:
        command = rx.sub(rep, command)
    return command


@dataclass(frozen=True)
class Match:
    rule_id: str
    description: str
    subject: str  # the text that was matched against (command or tool name)
    self_auth: bool = False


def _first_match(text: str, *, include_self_auth: bool = True) -> Match | None:
    norm = normalize_command(text)
    if include_self_auth:
        for rule in SELF_AUTH_RULES:
            if rule.pattern.search(norm):
                if rule.rule_id == "guard.self-disable" and _READ_ONLY_PREFIX.match(norm):
                    continue
                return Match(rule.rule_id, rule.description, text, self_auth=True)
    for rule in SHELL_RULES:
        if rule.pattern.search(norm):
            return Match(rule.rule_id, rule.description, text)
    return None


def _scan_script_files(command: str, cwd: str | os.PathLike | None) -> Match | None:
    """If the command runs a script file that exists, scan the script's content too."""
    if cwd is None:
        return None
    for m in _SCRIPT_RUN.finditer(command):
        name = m.group(1)
        if not name or name.startswith("-"):
            continue
        path = Path(name) if os.path.isabs(name) else Path(cwd) / name
        try:
            if not path.is_file() or path.stat().st_size > _MAX_SCRIPT_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hit = _first_match(content)
        if hit is not None:
            return Match(f"script:{hit.rule_id}", f"{hit.description} inside {name}", command, self_auth=hit.self_auth)
    return None


def evaluate(tool_name: str, tool_input: Any, cwd: str | os.PathLike | None = None) -> Match | None:
    """Return the first destructive-action rule a tool call matches, or None.

    ``cwd`` lets the guard read a script the command would run and scan it.
    """
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name in _SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        return _first_match(command) or _scan_script_files(command, cwd)
    if tool_name in _FILE_TOOLS_WITH_PATH:
        target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm_target = normalize_command(target)
        for rule in SELF_AUTH_RULES[1:]:
            if rule.pattern.search(norm_target) and (tool_name in _WRITE_TOOLS or rule.rule_id == "guard.key-access"):
                return Match(rule.rule_id, rule.description, target, self_auth=True)
        if tool_name in _WRITE_TOOLS and target.lower().endswith(_SCRIPT_EXT):
            body = " ".join(str(tool_input.get(k) or "") for k in ("content", "new_string", "new_source"))
            for e in tool_input.get("edits") or []:
                if isinstance(e, dict):
                    body += " " + str(e.get("new_string") or "")
            hit = _first_match(body, include_self_auth=False)
            if hit is not None:
                return Match(f"write:{hit.rule_id}", f"writes a script containing a {hit.description}", target)
        return None
    if tool_name.startswith("mcp__"):
        subject = tool_name + " " + json.dumps(tool_input, sort_keys=True, default=str)[:500]
        if _DESTRUCTIVE_TOOL_NAME.search(tool_name.split("__")[-1]):
            return Match("mcp.destructive-tool", "MCP tool whose name says it destroys data", subject)
        # A generic tool (e.g. a database server's `query` / `execute_sql`, or a
        # shell server's `run`) can still carry a destructive command in its
        # arguments: scan every string argument with the shell/SQL rules.
        for text in _string_values(tool_input):
            hit = _first_match(text)
            if hit is not None:
                desc = hit.description if hit.self_auth else f"{hit.description} inside an MCP tool call"
                return Match(hit.rule_id, desc, subject, self_auth=hit.self_auth)
    return None


def _string_values(value: Any, _depth: int = 0) -> list[str]:
    """All string leaves of a JSON-like value (bounded depth)."""
    if _depth > 8:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_values(v, _depth + 1)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _string_values(v, _depth + 1)]
    return []


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
    signing_key_hex,
    check: str | None = None,
    manual_reason: str | None = None,
    ttl_minutes: int = DEFAULT_TTL_MINUTES,
    timeout: float = 600.0,
) -> tuple[dict | None, dict]:
    """Run the check (if any) and, only if it passes, write a signed precondition.

    Returns (precondition or None, check_result). ``check_result`` has
    ``exit_code`` and ``output`` (combined stdout/stderr) for display.
    """
    import subprocess  # imported here: the hook path never needs it
    import uuid

    from .keytrust import coerce_signer
    from .signing import sign_hash_with_signer

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
    signer = coerce_signer(signing_key_hex)
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
        "signer": signer.public_key.hex(),
    }
    pc["precondition_hash"] = precondition_hash(pc)
    pc["signature"] = sign_hash_with_signer(pc["precondition_hash"], signer)
    d = preconditions_dir(cwd)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{pc['id']}.json").write_text(json.dumps(pc, indent=2, sort_keys=True), encoding="utf-8")
    return pc, result


def _key_set(trusted_key) -> set[str]:
    if trusted_key is None:
        return set()
    return {trusted_key} if isinstance(trusted_key, str) else set(trusted_key)


def check_precondition(pc: dict, *, trusted_key, now: datetime | None = None) -> str | None:
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
    keys = _key_set(trusted_key)
    if sig.get("verify_key") not in keys or pc.get("signer") != sig.get("verify_key"):
        return "precondition was signed by a key that is not a trusted approver"
    now = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(str(pc.get("expires")).replace("Z", "+00:00"))
    except ValueError:
        return "malformed expiry"
    if now >= expires:
        return "precondition has expired"
    return None


def _covers(scope: str, subject: str) -> bool:
    """`*` covers everything; otherwise the scope must appear as a whole token
    (so `--scope build` does not also cover `postgres-build-data`)."""
    if scope == "*":
        return True
    return re.search(r"(?<![\w.-])" + re.escape(scope) + r"(?![\w.-])", subject, re.IGNORECASE) is not None


def find_precondition(cwd: str | os.PathLike, subject: str, *, trusted_key) -> dict | None:
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
    approval: str | None = None  # Gate receipt_hash, when a person approved with a passkey

    def receipt_field(self) -> dict:
        out = {"decision": self.decision, "rule": self.rule, "precondition": self.precondition}
        if self.approval:
            out["approval"] = self.approval
        return out


def decide(tool_name: str, tool_input: Any, cwd: str | os.PathLike, *, trusted_key) -> Decision | None:
    """Guard decision for one tool call; None when no rule matches.

    ``trusted_key`` is one approver public key (hex), a set of them, or None
    (no approver exists, so every destructive call is denied).
    """
    m = evaluate(tool_name, tool_input, cwd)
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
    if not _key_set(trusted_key):
        return Decision("deny", m.rule_id, None,
                        f"perathos guard: blocked {m.description}. No approver key exists, so no safety "
                        f"precondition can be trusted. Run 'perathos keygen' or 'perathos approvers add', "
                        f"then:\n{hint}")
    pc = find_precondition(cwd, m.subject, trusted_key=trusted_key)
    if pc is None:
        return Decision("deny", m.rule_id, None,
                        f"perathos guard: blocked {m.description} ({m.rule_id}). No unexpired, signed safety "
                        f"precondition covers this command.\n{hint}")
    return Decision("allow", m.rule_id, pc["precondition_hash"],
                    f"perathos guard: allowed {m.description} under precondition {pc['id']} "
                    f"(scope {pc['scope']!r}, expires {pc['expires']})")
