"""PocketOS replay: the same agent mistake, without and with Perathos.

In April 2026 a coding agent deleted a company's production database volume,
and the backups stored on that same volume, in seconds. This script replays
that failure twice, in a throwaway folder, with a tiny SQLite "production
database":

  Run A  no Perathos: the delete runs; the data and its backups are gone, and
         the only record is the agent's own transcript.
  Run B  Perathos recorder + guard + timestamps: the delete is blocked; the
         person's backup check fails (the backups live on the volume being
         deleted); after an off-site copy the check passes, a signed
         precondition is created, the retry is allowed, and an evidence pack
         is exported and verified. Finally the log is cut, and verification
         against the independent timestamps catches it.

Nothing real is deleted: every "command" acts on files inside the demo
folder. Run B uses a temporary home folder, so it creates its own throwaway
signing key and never touches yours.

    pip install 'perathos[anchor]'
    python examples/pocketos_replay/replay.py [--offline] [--out DIR] [--json FILE]

--offline skips the network timestamp service (freetsa.org).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

SID = "pocketos-replay"
EVENTS: list[dict] = []
T0 = time.monotonic()


def say(kind: str, text: str) -> None:
    """Print a demo line and keep it for the --json transcript."""
    EVENTS.append({"t": round(time.monotonic() - T0, 2), "kind": kind, "text": text})
    prefix = {"h1": "\n=== ", "h2": "\n--- ", "agent": "agent  > ", "person": "person > ",
              "out": "         ", "ok": "  [ok] ", "bad": "  [!!] ", "note": "  "}.get(kind, "")
    print(prefix + text, flush=True)


# --------------------------------------------------------------------------- #
# The world: a project with a production database and backups on one volume
# --------------------------------------------------------------------------- #

def make_world(root: Path) -> None:
    vol = root / "volumes" / "pg-data"
    (vol / "backups").mkdir(parents=True)
    db = vol / "prod.db"
    con = sqlite3.connect(db)
    con.execute("create table customers (id integer primary key, name text, plan text)")
    con.executemany("insert into customers (name, plan) values (?, ?)",
                    [(f"customer-{i:04d}", "pro" if i % 3 else "team") for i in range(1, 1201)])
    con.commit()
    con.close()
    shutil.copyfile(db, vol / "backups" / "prod-backup.db")
    (root / "offsite").mkdir()
    (root / "check_backup.py").write_text(
        "import sqlite3, sys\n"
        "path = sys.argv[1]\n"
        "try:\n"
        "    n = sqlite3.connect(f'file:{path}?mode=ro', uri=True).execute('select count(*) from customers').fetchone()[0]\n"
        "except Exception as exc:\n"
        "    print(f'no restorable backup at {path}: {exc}'); sys.exit(1)\n"
        "print(f'backup at {path} restores: {n} customers'); sys.exit(0 if n > 0 else 1)\n",
        encoding="utf-8")


def rows(root: Path) -> str:
    db = root / "volumes" / "pg-data" / "prod.db"
    if not db.exists():
        return "production database: GONE"
    return f"production database: {count(db)} customers"


def count(db: Path) -> int:
    with closing(sqlite3.connect(db)) as con:  # closed, or Windows cannot delete the file
        return con.execute("select count(*) from customers").fetchone()[0]


def backups(root: Path) -> str:
    on_vol = (root / "volumes" / "pg-data" / "backups" / "prod-backup.db").exists()
    off = (root / "offsite" / "prod-backup.db").exists()
    return f"backups: on-volume={'yes' if on_vol else 'GONE'}, off-site={'yes' if off else 'none'}"


def run_effect(root: Path, command: str) -> str:
    """Simulate the agent's shell command inside the demo folder."""
    if command.startswith("railway volume list"):
        return "pg-data  10 GB  attached to: production"
    if command.startswith("railway volume delete pg-data"):
        shutil.rmtree(root / "volumes" / "pg-data", ignore_errors=True)
        return "Volume pg-data deleted."
    return ""


# --------------------------------------------------------------------------- #
# Perathos plumbing: call the real CLI exactly as Claude Code's hooks would
# --------------------------------------------------------------------------- #

class Perathos:
    def __init__(self, project: Path, home: Path):
        self.project, self.home = project, home
        self.env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
        self.n = 0

    def cli(self, *args: str, stdin: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "perathos", *args], input=stdin, text=True,
                              capture_output=True, cwd=str(cwd or self.project), env=self.env)

    def hook(self, flags: list[str], payload: dict) -> subprocess.CompletedProcess:
        payload = {"session_id": SID, "cwd": str(self.project),
                   "transcript_path": "", **payload}
        return self.cli("hooks", "record", *flags, stdin=json.dumps(payload))

    def tool_call(self, command: str, *, guard: bool = True) -> bool:
        """PreToolUse (+ guard), run if allowed, PostToolUse. Returns True if it ran."""
        self.n += 1
        tid = f"toolu_{self.n:02d}"
        say("agent", f"Bash: {command}")
        pre = self.hook(["--guard"] if guard else [], {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                                       "tool_use_id": tid, "tool_input": {"command": command}})
        if pre.stdout.strip():
            decision = json.loads(pre.stdout)["hookSpecificOutput"]
            if decision["permissionDecision"] == "deny":
                say("bad", "BLOCKED by perathos guard: " + decision["permissionDecisionReason"].splitlines()[0]
                    .replace("perathos guard: blocked ", ""))
                return False
        out = run_effect(self.project, command)
        if out:
            say("out", out)
        self.hook([], {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": tid,
                       "tool_input": {"command": command}, "tool_response": out})
        return True

    def end_turn(self, anchor: bool) -> None:
        r = self.hook(["--anchor"] if anchor else [], {"hook_event_name": "Stop"})
        if anchor and r.stderr.strip():
            say("note", "timestamp service unavailable, turn sealed without an anchor: " + r.stderr.strip()[:120])
        else:
            say("ok", "turn sealed with a signed checkpoint" + (" and an independent RFC 3161 timestamp" if anchor else ""))


# --------------------------------------------------------------------------- #
# The two runs
# --------------------------------------------------------------------------- #

def run_a(base: Path) -> None:
    say("h1", "RUN A - an agent with no flight recorder")
    root = base / "run-a"
    make_world(root)
    say("note", rows(root) + "; " + backups(root))
    say("note", 'Task given to the agent: "clean up the unused staging volume"')
    say("agent", "Bash: railway volume list")
    say("out", run_effect(root, "railway volume list"))
    say("agent", "Bash: railway volume delete pg-data --yes")
    say("out", run_effect(root, "railway volume delete pg-data --yes"))
    say("bad", rows(root) + "; " + backups(root))
    say("note", "Evidence left behind: the agent's own chat transcript, editable, unsigned, no independent time.")


def run_b(base: Path, offline: bool, out_dir: Path) -> int:
    say("h1", "RUN B - the same agent with Perathos (recorder + guard + timestamps)")
    root = base / "run-b"
    home = base / "home-b"
    home.mkdir()
    make_world(root)
    p = Perathos(root, home)
    keygen = p.cli("keygen")
    if keygen.returncode != 0:
        say("bad", "keygen failed: " + keygen.stderr.strip()[:200])
        return 1
    vk = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    say("note", "setup: perathos keygen; perathos hooks install --guard --anchor")
    say("note", rows(root) + "; " + backups(root))
    anchor = not offline

    say("h2", "Turn 1: the agent attempts the delete")
    p.tool_call("railway volume list")
    p.tool_call("railway volume delete pg-data --yes")
    say("agent", "(tries to approve itself)")
    p.tool_call("perathos precondition add --scope pg-data --manual 'agent says it is fine'")
    say("note", rows(root) + "; " + backups(root))
    p.end_turn(anchor)

    say("h2", "A person steps in: is there a restorable backup that survives this delete?")
    # Plain "python" when available keeps local paths out of the exported report.
    py = "python" if shutil.which("python") else f'"{sys.executable}"'
    check = f"{py} check_backup.py offsite/prod-backup.db"
    say("person", "perathos precondition add --scope pg-data --check \"python check_backup.py offsite/prod-backup.db\"")
    r = p.cli("precondition", "add", "--scope", "pg-data", "--check", check)
    if r.returncode == 0:
        say("bad", "unexpected: the check passed before an off-site copy existed")
        return 1
    say("bad", "check FAILED, no precondition created: the only backup lives on the volume being deleted")
    say("person", "copies the backup off the volume, then re-runs the check")
    shutil.copyfile(root / "volumes" / "pg-data" / "backups" / "prod-backup.db", root / "offsite" / "prod-backup.db")
    r = p.cli("precondition", "add", "--scope", "pg-data", "--check", check)
    if r.returncode != 0:
        say("bad", "check still failing: " + (r.stderr or r.stdout).strip()[:200])
        return 1
    expires = next((ln.split()[-1] for ln in r.stdout.splitlines() if ln.startswith("expires")), "?")
    say("ok", f"check passed; precondition signed for scope 'pg-data', expires {expires}")

    say("h2", "Turn 2: the agent retries")
    p.tool_call("railway volume delete pg-data --yes")
    say("note", rows(root) + "; " + backups(root))
    restored = count(root / "offsite" / "prod-backup.db")
    say("ok", f"restore from the off-site backup: {restored} customers")
    p.end_turn(anchor)

    say("h2", "After the incident: export and verify the evidence")
    v = p.cli("session", "verify", SID, "--verify-key", vk)
    for line in v.stdout.splitlines()[:9]:
        say("out", line)
    pack_dir = out_dir / "evidence-pack"
    e = p.cli("session", "export", SID, "--out", str(pack_dir))
    say("ok" if e.returncode == 0 else "bad", f"evidence pack exported: {pack_dir}.zip")
    ev = p.cli("evidence", "verify", str(pack_dir.with_suffix(".zip")), "--verify-key", vk)
    say("ok" if ev.returncode == 0 else "bad", "independent re-check of the pack: " + ev.stdout.splitlines()[0].split()[0])

    say("h2", "Tamper test: someone cuts turn 2 from the log and deletes the head file")
    log = root / ".perathos" / "sessions" / f"{SID}.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    first_seal = next(i for i, ln in enumerate(lines) if json.loads(ln)["kind"] == "checkpoint")
    log.write_text("\n".join(lines[: first_seal + 1]) + "\n", encoding="utf-8")
    (root / ".perathos" / "sessions" / f"{SID}.head.json").unlink(missing_ok=True)
    say("note", f"kept {first_seal + 1} of {len(lines)} receipts")
    only_log = p.cli("session", "verify", SID, "--verify-key", vk, "--anchors", str(base / "none.jsonl"))
    say("note", "check using the log alone:            " + only_log.stdout.splitlines()[0].split()[0])
    if anchor:
        with_anchors = p.cli("session", "verify", SID, "--verify-key", vk)
        err = next((ln for ln in with_anchors.stderr.splitlines() if "ERR_" in ln), "")
        status = with_anchors.stdout.splitlines()[0].split()[0]
        say("bad" if status == "INVALID" else "note",
            "check using the independent timestamps: " + status + ("  " + err.replace("[ERROR] ", "") if err else ""))
    else:
        say("note", "(run without --offline to see the independent timestamps catch the cut)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="skip the RFC 3161 timestamp service")
    ap.add_argument("--out", default=None, help="where to leave the evidence pack (default: a temp folder)")
    ap.add_argument("--json", default=None, help="also write the transcript of this run as JSON")
    args = ap.parse_args()
    base = Path(tempfile.mkdtemp(prefix="pocketos-replay-"))
    out_dir = Path(args.out) if args.out else base
    out_dir.mkdir(parents=True, exist_ok=True)
    run_a(base)
    code = run_b(base, args.offline, out_dir)
    say("h1", "Done. Demo files: " + str(base))
    if args.json:
        Path(args.json).write_text(json.dumps({"events": EVENTS}, indent=2), encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(main())
