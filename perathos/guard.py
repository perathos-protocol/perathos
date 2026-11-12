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
  * Commands whose text does not say what will run (``$CMD -rf build``,
    ``eval "$X"``, ``iex $x``, ``cmd /c %X%``, ``curl ... | sh``) are flagged
    as "unresolvable" and need a precondition like a destructive command.
    That covers the common forms on a shell command line only; a program
    name assembled from pieces, an alias, indirection inside interpreter
    code, a build-tool recipe and variables inside scripts or MCP arguments
    are not caught (``KNOWN_OPEN`` in tests/test_guard_hardening.py).
  * By default the signing key lives on the same machine. The guard refuses
    agent commands that create preconditions or touch ``.perathos/keys``, but
    an agent with unrestricted shell access could still reach the key some
    other way. For real separation, list approvers whose keys are held
    elsewhere (``perathos approvers add``; ``perathos precondition add
    --signer vault:... | gcpkms:... | command:...``, see
    ``perathos/signers.py``), so the agent's user cannot sign a precondition.
  * A precondition proves the check ran and passed. Whether that check is a
    meaningful test of the backup is the person's judgement.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from bisect import bisect_left, bisect_right
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


def _fold(s: str) -> str:
    """Case folding as close to re.IGNORECASE as a string compare gets
    (`ſ` folds to `s`; a character whose fold is longer keeps its lower case)."""
    if s.isascii():
        return s.lower()
    return "".join(c.casefold() if len(c.casefold()) == 1 else c.lower() for c in s)


class _RmtreeImportedByName:
    """`from shutil import rmtree [as r]` (or `import *`) or `import shutil as
    s`, followed anywhere later by a call through that name. One pass over the
    imports and one over the calls, so repeated or many distinct imports stay
    linear."""

    _IMPORT = re.compile(r"\bfrom\s+shutil\s+import\b|\bimport\s+shutil\s+as\s+(\w+)\b", re.IGNORECASE)
    _NAMED = re.compile(r"\brmtree\b(?:[^\S\n]+as[^\S\n]+(\w+))?|(\*)", re.IGNORECASE)
    _STOP = re.compile(r"[\n;]")
    _CALL = re.compile(r"\b(\w+)(\.rmtree)?\s*\(", re.IGNORECASE)

    def search(self, text: str) -> re.Match | None:
        after: dict[tuple[str, str], int] = {}  # call form -> earliest import end
        named = list(self._NAMED.finditer(text))
        named_starts = [m.start() for m in named]
        stops = [m.start() for m in self._STOP.finditer(text)]
        for m in self._IMPORT.finditer(text):
            if m.group(1) is not None:
                key = ("mod", _fold(m.group(1)))
            else:
                # the first `rmtree [as r]` or `*` in the rest of the import statement
                k = bisect_left(named_starts, m.end())
                s = bisect_left(stops, m.end())
                stop = stops[s] if s < len(stops) else len(text)
                if k == len(named) or named[k].end() > stop:
                    continue
                key = ("fn", _fold(named[k].group(1) or "rmtree"))
            after.setdefault(key, m.end())
        if not after:
            return None
        for c in self._CALL.finditer(text):
            name = _fold(c.group(1))
            keys = [(("mod", name), c.start()), (("fn", "rmtree"), c.start(2))] if c.group(2) else [(("fn", name), c.start())]
            for key, at in keys:
                if key in after and after[key] <= at:
                    return c
        return None


# Shell / CLI commands that can destroy data or the means to recover it.
# Matched against a normalised copy of the command (quotes removed, SQL
# comments collapsed), so `r""m -rf`, `k''eys` and `DROP/**/TABLE` match.
# Because quotes are gone, a rule cannot use a quote to find where an argument
# ends: `psql -c "DELETE FROM t" -h db` arrives as `psql -c DELETE FROM t -h db`.
#
# Reach is never capped. Rules of the form "keyword, any gap, target" are
# matched with ``_FirstStart`` (see there), which gives the same answer as the
# plain regex search but tries only the first keyword in each stretch of text
# the gap can span, so repeated keywords cannot make them quadratic.


class _FirstStart:
    """``pattern`` (which begins with ``start``) searched by trying only the
    first ``start`` match in each region; regions are separated by ``breaks``
    (None: the whole text is one region).

    Exact when the gap after ``start`` can absorb any text inside a region
    (`.*` within a line, `(?:[^\\s;&|]+\\s+)*` within a simple command,
    `(\\S+\\s+)*` anywhere): a match from a later start in the region is then
    also a match from the first one, so the later starts need not be tried."""

    def __init__(self, start: str, pattern: str, breaks: str | None):
        self.start = re.compile(start, re.IGNORECASE)
        self.full = re.compile(pattern, re.IGNORECASE)
        self.breaks = re.compile(breaks) if breaks is not None else None

    def search(self, text: str, pos: int = 0) -> re.Match | None:
        while True:
            m = self.start.search(text, pos)
            if m is None:
                return None
            hit = self.full.match(text, m.start())
            if hit is not None or self.breaks is None:
                return hit
            b = self.breaks.search(text, m.end())
            if b is None:
                return None
            pos = b.start()  # the next start may begin with the break itself (`;del`); b.start() >= m.end() > m.start()


class _Chain:
    """``start`` followed by several targets, each after a gap of ``gap``
    characters (`git push .* -f .* main`). A regex with two open gaps is
    quadratic; this takes, for each target, the leftmost match in its gap,
    and only when that fails downstream also a match starting on the
    character that ends the gap (a `\s` target such as `\sdown` can start
    on the newline itself). Like ``_FirstStart`` it tries only the first
    ``start`` in each region. The one form this does not reproduce is a
    target that is not leftmost and itself runs across a line end
    (`gcloud ... sql\ninstances`)."""

    def __init__(self, start: str, targets: list[str], gap: str = r"[^\n]", breaks: str = "\n"):
        self.start = re.compile(start, re.IGNORECASE)
        self.targets = [(re.compile(rf"{gap}*?(?:{t})", re.IGNORECASE), re.compile(t, re.IGNORECASE)) for t in targets]
        self.breaks = re.compile(breaks)

    def _from(self, text: str, p: int, k: int) -> bool:
        if k == len(self.targets):
            return True
        lazy, target = self.targets[k]
        m = lazy.match(text, p)
        if m is None:
            return False
        if self._from(text, m.end(), k + 1):
            return True
        b = self.breaks.search(text, p)
        if b is None:
            return False
        t = target.match(text, b.start())
        return t is not None and self._from(text, t.end(), k + 1)

    def search(self, text: str, pos: int = 0) -> re.Match | None:
        while True:
            m = self.start.search(text, pos)
            if m is None:
                return None
            if self._from(text, m.end(), 0):
                return m
            b = self.breaks.search(text, m.end())
            if b is None:
                return None
            pos = b.start()


def _rc(rule_id: str, start: str, targets: list[str], description: str, gap: str = r"[^\n]",
        breaks: str = "\n") -> Rule:
    """A "keyword, gap, target, gap, target" rule matched with ``_Chain``."""
    return Rule(rule_id, _Chain(start, targets, gap, breaks), description)  # type: ignore[arg-type]


def _rs(rule_id: str, start: str, rest: str, description: str, breaks: str | None = "\n") -> Rule:
    """A "keyword, gap, target" rule matched with ``_FirstStart``."""
    return Rule(rule_id, _FirstStart(start, start + rest, breaks), description)  # type: ignore[arg-type]


def _opts(prog: str) -> str:
    """Options before a subcommand, each with an optional value: `terraform
    -chdir=infra destroy`, `aws --profile p s3 rb`, `git -C repo reset`. A
    value is never the program's own name, so `prog -x prog -x ...` stays
    linear (an option whose value is literally the program name is the only
    form this leaves out)."""
    return rf"(?:-[^\s;&|]+\s+(?:(?!-|(?:{prog})\b)[^\s;&|]+\s+)?)*"


# Any words of the same simple command (no separator crossed).
_ARGS = r"(?:[^\s;&|]+\s+)*?"
_WORDS = "[;&|]"  # what an _ARGS gap cannot cross (it can cross a newline)
# The end of a word.
_END = r"(?=$|[\s;&|)])"
# A redirect target with a database-file extension. `.csv` and `.sql` are left
# out on purpose: `script > out.csv` is ordinary output, and `pg_dump db >
# backup.sql` makes a backup. Files under a test or fixture directory are
# generated test data and stay allowed.
_DATA_FILE = r"[^\s;&|<>]+\.(?:db|sqlite3?|duckdb|mdb|accdb|parquet)(?=\s|$|[;&|)])"
_TEST_DIR = r"(?:[^\s;&|<>]*[/\\])?(?:tests?|fixtures?|testdata|test_data|__fixtures__|__tests__|spec)[/\\]"
# Redirect targets that are not files.
_NOT_A_FILE = r"(?!/dev/(?:null|stdout|stderr|tty)\b|nul\b|\$null\b)"
# kubectl options that take a value, so `-n deployments-test` is never read
# as the resource type; the resource type must be a whole word.
_K8S_VALUE_OPT = (r"(?:-[nlofksc]|--(?:namespace|selector|context|cluster|user|kubeconfig|output|field-selector"
                  r"|filename|kustomize|grace-period|timeout|server|token|as|as-group|container))")
_K8S_OPTS = rf"(?:{_K8S_VALUE_OPT}\s+(?!kubectl\b)[^\s;&|]+\s+|(?!{_K8S_VALUE_OPT}\s)-[^\s;&|]+\s+)*"
_K8S_STATEFUL = r"(?:ns|namespaces?|pv|pvc|persistentvolume\w*|statefulsets?|sts|deployments?|deploy|all)(?=$|[\s/,.;&|)])"
# A git pathspec for the whole work tree: `.`, `./`, `:/`, `*`. (`--` with no
# pathspec after it is a no-op for `checkout` and an error for `restore`.)
_WHOLE_TREE = rf"(?::/\.?|\./?|\.?\*){_END}"
_GIT = rf"\bgit\s+{_opts('git')}"
_AWS = rf"\baws\s+{_opts('aws')}"
_GSUTIL = rf"\bgsutil\s+{_opts('gsutil')}"
_GCLOUD = rf"\bgcloud\s+{_opts('gcloud')}(?:(?:alpha|beta)\s+{_opts('gcloud')})?"
_DOCKER = rf"\bdocker\s+{_opts('docker')}"
_PODMAN = rf"\b(podman|nerdctl)\s+{_opts('podman|nerdctl')}"
_TERRAGRUNT = rf"\bterragrunt\s+{_opts('terragrunt')}(?:(?:run-all|run)\s+{_opts('terragrunt')}(?:--\s+)?)?"


class _GitRestore:
    """`git restore` that discards work in the whole tree: a whole-tree
    pathspec later in the same simple command, and `--worktree` / `-W` there or
    no `--staged` / `-S` (which would only unstage). Named files and
    directories (`git restore a.py`, `git restore src/`) are allowed. One pass
    per simple command: the last position of each option is noted, then each
    `git restore` start is checked against them."""

    _START = re.compile(rf"{_GIT}restore\b", re.IGNORECASE)
    _WHOLE = re.compile(rf"\s{_WHOLE_TREE}", re.IGNORECASE)
    _WORKTREE = re.compile(r"\s(?:--worktree\b|(?-i:-[A-Za-z]*W[A-Za-z]*)\b)", re.IGNORECASE)
    _STAGED = re.compile(r"\s(?:--staged\b|(?-i:-[A-Za-z]*S[A-Za-z]*)\b)", re.IGNORECASE)

    @staticmethod
    def _last(rx: re.Pattern, seg: str) -> int:
        last = -1
        for m in rx.finditer(seg):
            last = m.start()
        return last

    def search(self, text: str) -> re.Match | None:
        for seg in re.split(r"[;&|\n]", text):
            starts = list(self._START.finditer(seg))
            if not starts:
                continue
            whole, worktree, staged = (self._last(rx, seg) for rx in (self._WHOLE, self._WORKTREE, self._STAGED))
            for m in starts:
                if whole >= m.end() and (worktree >= m.end() or staged < m.end()):
                    return m
        return None


_DJANGO = r"manage\.py|django-admin|django"

SHELL_RULES: tuple[Rule, ...] = (
    _r("fs.rm-recursive",
       r"\brm\s+(-\S+\s+)*(-[a-z]*r|--recursive\b)|\brm\s+(-\S+\s+)*-[a-z]*f[a-z]*r",
       "recursive delete"),
    # cmd.exe takes switches anywhere on the line: `rmdir data /s /q`
    _rs("fs.win-delete", r"(^|[\s;&|(])(del|erase)\s+", rf"{_ARGS}/[sq]\b", "Windows recursive or quiet delete", _WORDS),
    _rs("fs.win-delete", r"(^|[\s;&|(])(rd|rmdir)\s+", rf"{_ARGS}/s\b", "Windows recursive or quiet delete", _WORDS),
    _r("fs.win-delete", r"(^|[\s;&|(])format\s+[a-z]:", "Windows recursive or quiet delete"),
    _rs("fs.ps-delete", r"\b(remove-item|ri|del|erase|rd|rmdir|rm)\s+", r"(\S+\s+)*-(r|recurse|rec|force)\b",
        "PowerShell recursive delete", None),
    _rs("fs.find-delete", r"\bfind\b", r".*\s(-delete\b|-exec\s+rm\b)", "find -delete"),
    _r("fs.truncate-or-overwrite", r"\btruncate\s+(-s\s*0|--size[= ]0)\b|\bshred\b|\bmv\s+\S+\s+/dev/null",
       "file truncated, overwritten or shredded"),
    _rs("fs.truncate-or-overwrite", r"\bdd\s+", r".*\bof=(?!/dev/null)", "file truncated, overwritten or shredded"),
    # `cp /dev/null file`, `cat /dev/null > file` and PowerShell `Clear-Content`
    # empty any file. (Redirects are judged on the structure view: REDIRECT_RULES.)
    _r("fs.redirect-truncate",
       rf"\bcp\s+(?:-\S+\s+)*/dev/null\s+{_NOT_A_FILE}\S|\bcat\s+/dev/null\s*>(?!>)\|?\s*{_NOT_A_FILE}\S|\bclear-content\b",
       "file emptied by a redirect"),
    _r("fs.interpreter-delete", r"shutil\)?\.rmtree|\brimraf\b|FileUtils\.rm_rf", "delete through an interpreter one-liner"),
    _rs("fs.interpreter-delete", r"\.(rm|rmSync|rmdir|rmdirSync|promises\.rm)\s*\(", r".*recursive",
        "delete through an interpreter one-liner"),
    _rs("fs.interpreter-delete", r"\bos\.(remove|unlink|rmdir|removedirs)\s*\(", r".*\*",
        "delete through an interpreter one-liner"),
    # `from shutil import rmtree; rmtree(p)`, `... import rmtree as r; r(p)`,
    # `from shutil import *; rmtree(p)`, `import shutil as s; s.rmtree(p)`
    Rule("fs.python-rmtree", _RmtreeImportedByName(),  # type: ignore[arg-type]
         "delete through an interpreter one-liner (rmtree imported by name)"),
    _rs("fs.robocopy-mirror", r"\brobocopy\b", r".*\s/(mir|purge)\b",
        "robocopy /MIR or /PURGE (deletes files missing from the source)"),
    _r("fs.ps-format", r"\b(format-volume|clear-disk|remove-partition)\b", "PowerShell volume format or disk wipe"),
    # Discarding work in the whole tree is flagged: `checkout -f`, `checkout
    # [<tree>] [--] .`, `restore .` / `restore :/` unless it only unstages
    # (`--staged` without `--worktree`). Named files or directories
    # (`checkout -- a.py`, `checkout feature -- ci.yml`, `restore src/`) are not.
    _r("git.destructive",
       rf"{_GIT}(clean\s+-\S*[fd]|branch\s+(?-i:-D)\b|stash\s+(drop|clear)|filter-branch|reflog\s+expire|update-ref\s+-d)",
       "git command that discards work"),
    _rs("git.destructive", rf"{_GIT}reset\s+", rf"{_ARGS}--hard\b", "git command that discards work", _WORDS),
    _rs("git.destructive", rf"{_GIT}checkout\s+", rf"{_ARGS}(-f\b|--force(?![\w-])|(--\s+)?{_WHOLE_TREE})",
        "git command that discards work", _WORDS),
    _rs("git.destructive", rf"{_GIT}switch\s+", rf"{_ARGS}(-f\b|--force(?![\w-])|--discard-changes\b)",
        "git command that discards work", _WORDS),
    Rule("git.destructive", _GitRestore(), "git command that discards work"),  # type: ignore[arg-type]
    _rc("git.force-push-main", r"\bgit\s+push\b", [r"--force\b|-f\b|--mirror\b", r"\b(main|master|prod|production)\b"],
        "force push to a main branch"),
    _r("git.force-push-main", r"\bgit\s+push\s+--mirror\b", "force push to a main branch"),
    _rs("git.push-main-rewrite", r"\bgit\s+push\b",
        r".*\s(\+\S*\b(main|master|prod|production)\b|:(refs/heads/)?(main|master|prod|production)\b)",
        "forced overwrite or delete of a main branch on the remote"),
    _rc("git.push-main-rewrite", r"\bgit\s+push\b", [r"--delete\b|\s-d\b", r"\b(main|master|prod|production)\b"],
        "forced overwrite or delete of a main branch on the remote"),
    _r("git.repo-delete", r"\bgh\s+repo\s+delete\b", "GitHub repository delete"),
    _r("fs.mkfs", r"(^|[\s;&|(])mkfs(\.\w+)?\s", "filesystem format"),
    _rs("fs.rsync-delete", r"\brsync\b", r".*\s--(delete(-\w+)*|remove-source-files)\b", "rsync that deletes files"),
    _r("db.dropdb", r"\bdropdb\b", "PostgreSQL dropdb"),
    _rs("db.mysqladmin-drop", r"\bmysqladmin\b", r".*\sdrop\b", "mysqladmin drop"),
    _r("db.migrate-reset",
       rf"\b(prisma\s+{_opts('prisma')}migrate\s+{_opts('prisma')}reset|rails\s+db:(drop|reset)|supabase\s+db\s+reset"
       r"|heroku\s+pg:reset)\b",
       "database reset"),
    _rs("db.prisma-force-reset", rf"\bprisma\s+{_opts('prisma')}db\s+push\b", r".*\s--(force-reset|accept-data-loss)\b",
        "prisma db push that drops data"),
    _r("db.django-flush",
       rf"(?:\b(?:manage\.py|django-admin)|\s-m\s+django)\s+{_opts(_DJANGO)}(flush|reset_db)\b",
       "Django flush (deletes every row)"),
    _r("iac.terraform-destroy", rf"\bterraform\s+{_opts('terraform')}destroy\b", "terraform destroy"),
    _rs("iac.terraform-destroy", rf"\bterraform\s+{_opts('terraform')}apply\b", r".*-destroy\b", "terraform destroy"),
    _r("iac.tofu-destroy", rf"\btofu\s+{_opts('tofu')}destroy\b", "OpenTofu destroy"),
    _rs("iac.tofu-destroy", rf"\btofu\s+{_opts('tofu')}apply\b", r".*-destroy\b", "OpenTofu destroy"),
    _r("iac.terragrunt-destroy", rf"{_TERRAGRUNT}destroy\b", "terragrunt destroy"),
    _rs("iac.terragrunt-destroy", rf"{_TERRAGRUNT}apply\b", r".*-destroy\b", "terragrunt destroy"),
    _r("iac.pulumi-destroy", r"\bpulumi\s+destroy\b", "pulumi destroy"),
    _r("k8s.delete", rf"\bkubectl\s+{_K8S_OPTS}delete\s+{_K8S_OPTS}{_K8S_STATEFUL}",
       "kubectl delete of stateful resources"),
    _r("k8s.helm-uninstall", r"\bhelm\s+(uninstall|delete)\b", "helm uninstall"),
    _r("cloud.aws-delete",
       rf"{_AWS}(s3\s+rb\b|s3\s+rm\s+--recursive|rds\s+delete-|dynamodb\s+delete-table|ec2\s+delete-(volume|snapshot)"
       r"|backup\s+delete-|s3api\s+delete-bucket\b|cloudformation\s+delete-stack\b)",
       "AWS delete of storage or backups"),
    _rs("cloud.aws-delete", rf"{_AWS}s3\s+rm\b", r".*--recursive", "AWS delete of storage or backups"),
    _rs("cloud.aws-s3-sync-delete", rf"{_AWS}s3\s+sync\b", r".*\s--delete\b",
        "aws s3 sync --delete (deletes objects missing from the source)"),
    # gcloud takes global options and release tracks (`alpha`, `beta`) before the group
    _r("cloud.gcloud-delete",
       rf"{_GCLOUD}(sql\s+(instances|databases|backups)|compute\s+(disks|snapshots)|storage\s+buckets|firestore\s+databases"
       rf"|spanner\s+(instances|databases)|filestore\s+(instances|backups))\s+{_opts('gcloud')}delete\b"
       rf"|{_GCLOUD}(storage\s+{_opts('gcloud')}rm|projects\s+{_opts('gcloud')}delete)\b",
       "Google Cloud delete of storage or backups"),
    _rc("cloud.gcloud-delete", r"\bgcloud\s+",
        [r"\b(sql\s+instances|compute\s+disks|compute\s+snapshots|storage\s+(buckets\s+)?rm)\b", r"\bdelete\b"],
        "Google Cloud delete of storage or backups"),
    _r("cloud.gsutil-delete", rf"{_GSUTIL}rb\b", "gsutil bucket remove, recursive or wildcard delete"),
    _rs("cloud.gsutil-delete", rf"{_GSUTIL}rm\b", r".*\s-([a-z]*[ra][a-z]*|-recursive|-all-versions)\b",
        "gsutil bucket remove, recursive or wildcard delete"),
    _rs("cloud.gsutil-delete", rf"{_GSUTIL}rm\b", r".*\*", "gsutil bucket remove, recursive or wildcard delete"),
    _r("cloud.rclone-delete", rf"\brclone\s+{_opts('rclone')}(purge|delete)\b", "rclone purge / delete"),
    _rs("cloud.az-delete", r"\baz\s+(sql|storage|disk|snapshot|backup|cosmosdb|group)\b", r".*\bdelete\b",
        "Azure delete of storage or backups"),
    _r("paas.railway", r"\brailway\s+(down|volume\s+delete|delete)\b", "Railway delete"),
    _r("paas.vercel", r"\bvercel\s+(remove|rm)\b", "Vercel remove"),
    _r("paas.fly", r"\bfly(ctl)?\s+(volumes?\s+(destroy|delete)|apps?\s+destroy|postgres\s+destroy)\b", "Fly destroy"),
    _r("paas.neon", r"\bneon(ctl)?\s+(branches?|projects?|databases?)\s+delete\b", "Neon delete"),
    _r("paas.firebase", rf"\bfirebase\s+{_opts('firebase')}(firestore:delete|database:remove)\b", "Firebase data delete"),
    _r("paas.heroku", rf"\bheroku\s+{_opts('heroku')}(apps:destroy|destroy|pg:backups:delete|addons:destroy)\b",
       "Heroku destroy"),
    _r("docker.volume", rf"{_DOCKER}volume\s+(rm|prune)", "Docker volume delete"),
    _rs("docker.volume", rf"{_DOCKER}system\s+prune\b", r".*--volumes", "Docker volume delete"),
    _rc("docker.volume", r"\bdocker([ -])compose\b", [r"\sdown\b", r"\s(-v\b|--volumes\b)"], "Docker volume delete"),
    # podman and nerdctl take docker's volume commands; `system reset` wipes all storage
    _r("container.volume", rf"{_PODMAN}(volume\s+(rm|prune)|system\s+reset\b)", "podman / nerdctl volume delete"),
    _rs("container.volume", rf"{_PODMAN}system\s+prune\b", r".*--volumes", "podman / nerdctl volume delete"),
    _rc("container.volume", r"\b(podman|nerdctl)([ -])compose\b", [r"\sdown\b", r"\s(-v\b|--volumes\b)"],
        "podman / nerdctl volume delete"),
)

# Redirects, matched against the structure view (quotes removed but a `;` or
# `>` inside a quoted argument blanked), so `echo 'DELETE FROM t;' > q.sql` is
# an ordinary write. `> file` with no command (and `: > file`) empties any
# file; an ordinary `cmd > file` is flagged only when it would overwrite a
# database file outside a test directory. `> /dev/null`, `> NUL` and `=>` are
# not redirects to a file.
REDIRECT_RULES: tuple[Rule, ...] = (
    _r("fs.truncate-or-overwrite", r"(^|[;&|])\s*:\s*>\s*\S", "file truncated, overwritten or shredded"),
    _r("fs.redirect-truncate",
       rf"(?:^|[;(]|&&|\|\|)\s*>\|?\s*{_NOT_A_FILE}[^\s>&|;]|(?<![>\d=-])>(?!>)\|?\s*(?!{_TEST_DIR}){_DATA_FILE}",
       "file emptied by a redirect"),
)

# Query-language rules (SQL, Redis, MongoDB). On a shell command line they
# apply only to text that can reach a database (see ``_query_texts``): a
# simple command that runs a database client (`psql`, `docker exec db psql`,
# `ssh db mysql`), a whole pipeline that feeds one (`echo 'DROP TABLE t' |
# psql`), and every other simple command except those that only carry text
# (`git commit -m`, `gh pr create --title`, `echo`, `grep`...). A client that
# reads a file or stdin redirect (`psql -f f.sql`, `sqlite3 db < q.sql`) makes
# the whole line count, since the file may have been written earlier on it.
# In scripts, MCP arguments and file writes the rules apply to all the text.
_ALTER_TABLE = r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?[\w.$\[\]]+\s+"
_DROP_WHAT = (r"drop\s+(?:column\b|constraint\b"
              r"|(?!index\b|key\b|primary\b|foreign\b|default\b|check\b|trigger\b|if\b)\w+)")
QUERY_RULES: tuple[Rule, ...] = (
    _r("sql.drop", r"\bdrop\s+(database|schema|table)\b", "SQL DROP"),
    _r("sql.truncate", r"\btruncate\s+(table\s+)?[\w.$\[\]]+", "SQL TRUNCATE"),
    # The statement ends at `;`, a newline, `)`, a shell separator or redirect
    # or a `--` comment. An alias or a LIMIT may follow the table; a WHERE may not.
    _r("sql.delete-all",
       r"\bdelete\s+from\s+[\w.$\[\]]+(?:\s+(?:as\s+)?(?!where\b|limit\b)\w+)?(?!\s*where\b)(?:\s+limit\s+\d+)?"
       r"\s*(?:$|[;)|&\n<>]|--\s)",
       "SQL DELETE without WHERE"),
    _r("sql.alter-drop", _ALTER_TABLE + _DROP_WHAT, "SQL ALTER TABLE ... DROP COLUMN / CONSTRAINT"),
    _rs("sql.alter-drop", _ALTER_TABLE, r"[^;\n]*?,\s*" + _DROP_WHAT, "SQL ALTER TABLE ... DROP COLUMN / CONSTRAINT",
        "[;\n]"),
    _r("db.redis-flush", r"\bflush(all|db)\b", "Redis FLUSHALL / FLUSHDB"),
    _r("db.mongo-drop", r"\.drop(database)?\s*\(", "MongoDB drop"),
    _r("db.mongo-delete-all", r"\.(deleteMany|remove)\s*\(\s*\{\s*\}\s*[,)]|\.deleteMany\s*\(\s*\)",
       "MongoDB delete of every document"),
)
# With a database client on the line, the statement may also end at the
# client's next option: `psql -c "DELETE FROM users" -h db`.
CLIENT_QUERY_RULES: tuple[Rule, ...] = (
    _r("sql.delete-all",
       r"\bdelete\s+from\s+[\w.$\[\]]+(?:\s+(?:as\s+)?(?!where\b|limit\b)\w+)?(?!\s*where\b)(?:\s+limit\s+\d+)?"
       r"\s+-{1,2}[a-z]",
       "SQL DELETE without WHERE"),
)
_DB_CLIENT = re.compile(
    r"(?<![\w-])(?:psql|pgcli|mysql|mariadb|mysqlsh|mycli|sqlite3?|litecli|sqlcmd|osql|isql|invoke-sqlcmd|sqlplus"
    r"|cockroach|duckdb|clickhouse(?:-client)?|mongo|mongosh|redis-cli|valkey-cli|cqlsh|snowsql|bq|trino|presto|usql"
    r"|vsql|beeline|impala-shell|dbshell|dbconsole|prisma|wrangler|turso|supabase|hdbsql|db2)(?:\.exe)?(?![\w-])",
    re.IGNORECASE)
# Programs whose arguments are text, not a query: a commit message, a PR
# title, an echoed or searched string.
_TEXT_ONLY_PROGRAMS = frozenset({
    "git", "gh", "glab", "hub", "hg", "svn", "jj", "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "sed", "awk", "jq", "yq", "write-host", "write-output", "select-string", "sls",
})
# ...unless the text-only program is told to run a command: `git -c
# alias.x='!psql ...'`, `git -c core.sshCommand=...`, awk `system(...)`.
_TEXT_PROGRAM_RUNS = re.compile(r"\s-c\s+\S*(?:alias|command|editor|pager|hook)|\bsystem\s*\(", re.IGNORECASE)
_PROGRAM = re.compile(r"^[\s({!]*(?:(?:sudo|env|command|builtin|nohup|time|exec)\s+(?:-\S+\s+)*)*"
                      r"(?:[a-z_]\w*=\S*\s+)*([^\s]+)", re.IGNORECASE)
_CLIENT_READS_INPUT = re.compile(r"\s(?:-f|--file|-i|--init-file|\.read|source)(?:\s|=)|<", re.IGNORECASE)

# The whole text is matched, as before; input above these sizes is not
# matched at all and is denied (fail closed): a shell command, or the total of
# a script write's content or of an MCP call's string arguments. The content
# cap keeps the worst case (repeated keywords make some rules quadratic) well
# inside the hook's 10 s timeout.
MAX_COMMAND_CHARS = 65536
MAX_CONTENT_CHARS = 700_000

# "Unresolvable" commands: the text does not say what will run, so no pattern
# above can judge it. They are treated like a destructive command (denied
# unless a precondition or approval covers them). Matched against the
# structure view (see ``_structure_view``), not the quote-stripped text, so a
# `|`, `;` or `$` inside an ordinary quoted argument does not count.
_SH = r"(?:ba|z|da|k|a|fi)?sh"
_INTERP = rf"(?:{_SH}|python[\d.]*|node|perl|ruby|php|pwsh|powershell|cmd)(?:\.exe)?"
_VAR = r"(?:\$\{[^}\n]*\}|\$[a-z_]\w*(?!\w))"
_WORD_END = r"(?:\s|$|[;&|)])"
# `$HOME/bin/tool`, `$(npm bin)/eslint`: the directory is variable but the
# program name is written out, so the other rules can still read it.
_NOT_LITERAL_PATH = r"(?![/\\][^\s$`;&|()]*[^\s$`;&|()/\\](?:\s|$|[;&|)]))"
# Where a command starts: line start, after a separator, inside `$(`, after a
# shell keyword or `sh -c`; then any wrappers and `NAME=value` prefixes.
_CP = (rf"(?:^|[;&|\n]|\$\(|\b(?:if|then|else|elif|do|while|until)\s|\b{_SH}\s+(?:-\w+\s+)*?-\w*c\s)\s*(?:!\s+)?"
       r"(?:(?:sudo|exec|command|builtin|nohup|time|env|xargs|nice|watch|timeout[^\S\n]+[\d.]+\w?)[^\S\n]+)*"
       r"(?:[a-z_]\w*=\S*[^\S\n]+)*")  # `[^\S\n]`: a newline is itself a command start, so chaining across it adds nothing
# An interpreter reading its program from the pipe: `| sh`, `| bash -s -- -y`,
# `| python -`, `| iex`. `| python -m json.tool` and `| node x.js` are not.
_STDIN_SINK = (rf"(?<!\|)\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:{_INTERP}|iex|invoke-expression)"
               r"(?:\s+-s\b[^;&|\n]*|(?:\s+-(?!c\b|e\b|m\b|r\b|command\b|file\b)\S*)*)|(?:source|\.)\s+/dev/stdin)"
               r"\s*(?:$|[;&|\n)])")
_DL = (r"(?:curl|wget|aria2c|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|bitsadmin|certutil"
       r"|downloadstring|downloadfile|downloaddata)")
_PREFILTER_REMOTE = re.compile(rf"\b{_DL}\b", re.IGNORECASE)
# The usual shell-setup idioms: `eval "$(ssh-agent -s)"`, `eval "$(pyenv init -)"`.
_EVAL_OK = (r"\$\((?:ssh-agent(?:\s+-s)?|(?:\S*/)?brew\s+shellenv|(?:pyenv|rbenv|nodenv|direnv|starship|zoxide|fnm|mise|opam)"
            r"\s+[\w .=-]*|minikube\s+(?:-p\s+\S+\s+)?docker-env|conda\s+shell\.\w+\s+hook|docker-machine\s+env[\w -]*)\)"
            r"\s*(?:$|[;&|\n])")

class _DownloadThenRun:
    """A download that names a file (`curl -o i.sh URL`, `wget URL/i.sh`),
    ended by `&&`, `;` or a newline, and a later command that runs that name
    (`bash i.sh`, `./i.sh`, `sudo /tmp/i.sh`, `& .\\i.ps1`). The regex form of
    this (a backreference after two open gaps) is cubic; this finds the same
    matches in linear time: every command start is parsed once into the names
    it could run, and only the first download of each simple command is read,
    because a later one in the same command can only name a subset."""

    _DL_RX = re.compile(rf"\b{_DL}\b", re.IGNORECASE)
    _SEP = re.compile(r"[\n;&|]")
    _NAME = re.compile(r"(?<=[/\s=])[\w-][\w.-]*(?=[\s;&]|\Z)")
    _NAME_AT = re.compile(r"[\w-][\w.-]*(?=[\s;&])")
    _RUN_SEP = re.compile(r"(?=&&|;|\n)")
    _LEAD = re.compile(r"\s*")
    _SUDO = re.compile(r"sudo\s+", re.IGNORECASE)
    _AMP = re.compile(r"&\s*")
    _INTERP_RX = re.compile(rf"(?:{_INTERP}|source)\s+", re.IGNORECASE)
    _FLAG = re.compile(r"-\S+\s+")
    _TOKEN = re.compile(rf"(?:[\w.~/\\-]*[/\\])?([\w-][\w.-]*){_WORD_END}", re.IGNORECASE)

    def _names_run_at(self, text: str, t: int, seen_flags: set[int]) -> list[str]:
        out: list[str] = []

        def token(p: int) -> None:
            m = self._TOKEN.match(text, p)
            if m:
                out.append(_fold(m.group(1)))

        bases = [t]
        if text[t:t + 4].casefold() == "sudo":  # casefold: re.IGNORECASE also reads `ſudo` as sudo
            s = self._SUDO.match(text, t)
            if s:
                bases.append(s.end())
        for b in bases:
            token(b)
            if text.startswith("&", b):
                token(self._AMP.match(text, b).end())
            i = self._INTERP_RX.match(text, b)
            if i:
                p = i.end()
                while p not in seen_flags:  # a flag run already walked (for a later separator) adds nothing
                    seen_flags.add(p)
                    token(p)
                    f = self._FLAG.match(text, p)
                    if f is None:
                        break
                    p = f.end()
        return out

    def search(self, text: str) -> re.Match | None:
        # name -> last separator (`&&`, `;`, newline) followed by a command that runs it.
        # Separators are taken right to left so the first record is the last one,
        # and whitespace runs and flag runs shared by several separators are walked once.
        run_at: dict[str, int] = {}
        n = len(text)
        lead: dict[int, int] = {}
        names_at: dict[int, list[str]] = {}
        seen_flags: set[int] = set()
        for r in reversed([m.start() for m in self._RUN_SEP.finditer(text)]):
            q = r + (2 if text.startswith("&&", r) else 1)
            j = q
            while j < n and j not in lead and text[j].isspace():
                j += 1
            t = lead[q] = lead.get(j, j)
            if t not in names_at:
                names_at[t] = self._names_run_at(text, t, seen_flags)
            for name in names_at[t]:
                run_at.setdefault(name, r)
        if not run_at:
            return None
        pos = 0
        while True:
            m = self._DL_RX.search(text, pos)
            if m is None:
                return None
            sm = self._SEP.search(text, m.end())
            if sm is None:
                return None
            s = sm.start()
            if text[s] in "\n;" or text.startswith("&&", s):
                for c in self._NAME.finditer(text[m.end():s]):
                    if run_at.get(_fold(c.group()), -1) >= s:
                        return m
            if text[s] == "\n":
                # the regex's `[/\s=]` before the name can be the newline itself, so the
                # first word of the next line is a candidate too, ended by that line's separator
                c = self._NAME_AT.match(text, s + 1)
                s2 = self._SEP.search(text, c.end()) if c else None
                if s2 is not None and (text[s2.start()] in "\n;" or text.startswith("&&", s2.start())):
                    if run_at.get(_fold(c.group()), -1) >= s2.start():
                        return m
            pos = s + 1


REMOTE_SCRIPT_RULES: tuple[Rule, ...] = (
    _rs("unresolvable.remote-script", rf"\b{_DL}\b", rf"[^;&\n]*{_STDIN_SINK}",
        "download piped into an interpreter (the guard cannot see what it would run)", "[;&\n]"),
    _r("unresolvable.remote-script",
       rf"(?:\b(?:{_INTERP}|source)|(?:^|[\s;&|(])\.)\s+(?:-\S+\s+)*<?\s*<\(\s*(?:sudo\s+)?{_DL}\b",
       "download substituted into an interpreter (the guard cannot see what it would run)"),
    _rs("unresolvable.remote-script", r"\b(?:eval|iex|invoke-expression)\b", rf"[^;|\n]*\b{_DL}\b",
        "download evaluated as a command (the guard cannot see what it would run)", "[;|\n]"),
    _r("unresolvable.remote-script", rf"\s(?:-\w*c|-e|-r|-command|/c)\s+\$\(\s*{_DL}\b|{_CP}\$\(\s*{_DL}\b",
       "download evaluated as a command (the guard cannot see what it would run)"),
    _rs("unresolvable.remote-script", r"\[scriptblock\]::create\(", rf"[^\n]*\b{_DL}\b",
        "download evaluated as a command (the guard cannot see what it would run)"),
    Rule("unresolvable.remote-script", _DownloadThenRun(),  # type: ignore[arg-type]
         "download saved and then run (the guard cannot see what it would run)"),
)

INDIRECT_RULES: tuple[Rule, ...] = (
    _r("unresolvable.indirect", rf"{_CP}\$\((?![^()\n]*\)[/\\][^\s$`;&|()]*[^\s$`;&|()/\\](?:\s|$|[;&|)]))",
       "command produced by a command substitution (the guard cannot tell what would run)"),
    _rs("unresolvable.indirect", rf"{_CP}eval\s+(?!{_EVAL_OK})", r"[^;&|\n]*\$",
        "eval of a variable or substitution (the guard cannot tell what would run)", "[;&|\n]"),
    _rs("unresolvable.indirect", rf"\b(?:{_INTERP}|psql|mysql|su|wsl)\s+",
        r"(?:[^\s;&|]+\s+)*?(?:-\w*c|-e|-r|-command|--command|/c|/k)\s+(?:\$[\w{(]|[%!]\w+[%!])",
        "command string held in a variable (the guard cannot tell what would run)", _WORDS),
    _r("unresolvable.indirect", r"\s-exec(?:dir)?\s+\$[\w{(]|\btrap\s+\$[\w{(]",
       "command string held in a variable (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       rf"{_CP}(?:{_INTERP}|source|\.)\s+(?:-(?!c\b|e\b|r\b|command\b)\S+\s+)*{_VAR}{_WORD_END}",
       "script whose path is held in a variable (the guard cannot read it)"),
    _r("unresolvable.indirect", _STDIN_SINK,
       "text piped into an interpreter (the guard cannot tell what would run)"),
    _rc("unresolvable.indirect", rf"\b{_SH}\b", [r"<<<", r"\$"],
        "substitution fed to a shell as its script (the guard cannot tell what would run)", r"[^;&|\n]", "[;&|\n]"),
    _r("unresolvable.indirect", rf"(?:\b(?:{_SH}|source)|(?:^|[\s;&|(])\.)\s+(?:-\S+\s+)*<?\s*<\(",
       "substitution fed to a shell as its script (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       r"(?<![>\d&])&\s*\$[\w{(]|\b(?:iex|invoke-expression)\s+(?:-command\s+)?[$(@]"
       r"|\b(?:start-process|saps)\s+(?:-filepath\s+)?\$",
       "PowerShell call of a variable or expression (the guard cannot tell what would run)"),
    _rs("unresolvable.indirect", r"\[scriptblock\]::create\(", r"[^)\n]*\$",
        "PowerShell call of a variable or expression (the guard cannot tell what would run)", "[)\n]"),
    _rs("unresolvable.indirect", r"\b(?:invoke-command|icm)\b", r"[^;|\n]*-scriptblock\s+\$",
        "PowerShell call of a variable or expression (the guard cannot tell what would run)", "[;|\n]"),
    _rs("unresolvable.indirect", r"\b(?:powershell|pwsh)(?:\.exe)?\b", r"[^;|&\n]*\s-(?:e|ec|en\w*)\s+[a-z0-9+/=]{8,}",
        "PowerShell encoded command (the guard cannot tell what would run)", "[;|&\n]"),
    _r("unresolvable.indirect",
       r"(?:^|[&|(\n])\s*@?(?:call\s+|start\s+(?:/\w+\s+)*)?[%!]\w+[%!](?:\s|$|[&|)])"
       r"|\bdo\s+@?(?:call\s+)?%%?~?\w+%?(?:\s|$)",
       "cmd variable in command position (the guard cannot tell what would run)"),
)
# `$CMD -rf build`: a variable where the program name should be. Skipped for
# the PowerShell tool, where `$x = 1`-style statements start with a variable
# and `$x args` does not run anything.
POSIX_INDIRECT_RULES: tuple[Rule, ...] = (
    _r("unresolvable.indirect",
       rf"{_CP}{_VAR}{_NOT_LITERAL_PATH}(?!\+\+|--|[.\[:]|\s*[+\-*/]?=(?!=))",
       "variable in command position (the guard cannot tell what would run)"),
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
    r"(?:^|[\s;&|(])(?:\.?/|bash\s+|sh\s+|zsh\s+|source\s+|\.\s+|python3?\s+|node\s+|pwsh\s+(?:-\S+\s+)*|powershell\s+(?:-\S+\s+)*)"
    r"([^\s;&|)<>\"']+)", re.I)
# `psql ... -f x.sql`, `mysql ... < x.sql`, `sqlite3 ... < x.sql` on the same line
_SCRIPT_RUN_DB = (
    (re.compile(r"(?:^|[\s;&|(])psql\b", re.I), re.compile(r"\s-f\s+([^\s;&|)<>\"']+)")),
    (re.compile(r"(?:^|[\s;&|(])(?:mysql|sqlite3)\b", re.I), re.compile(r"<\s*([^\s;&|)<>\"']+)")),
)
_MAX_SCRIPT_BYTES = 1 << 20
_CMD_NORMALISERS = (
    (re.compile(r"""['"`]"""), ""),            # r""m -rf, k''eys
    (re.compile(r"\\\r?\n"), " "),             # line continuations
)
_SPACES = re.compile(r"[ \t]+")


def _drop_block_comments(command: str) -> str:
    """`/* ... */` collapsed to a space, as `re.sub(r"/\*.*?\*/", " ", ..., re.S)`
    would, but linear when a `/*` is never closed."""
    out, i = [], 0
    while True:
        a = command.find("/*", i)
        b = command.find("*/", a + 2) if a >= 0 else -1
        if b < 0:
            break
        out += [command[i:a], " "]
        i = b + 2
    out.append(command[i:])
    return "".join(out)


def normalize_command(command: str) -> str:
    """The text rules are matched against: quotes stripped, comments collapsed."""
    for rx, rep in _CMD_NORMALISERS:
        command = rx.sub(rep, command)
    return _SPACES.sub(" ", _drop_block_comments(command))


_PATH_WORD = re.compile(r"(?<![^\s=:])[^\s=:/]*+/[^\s=:]*")  # a word (split at whitespace, `=`, `:`) with a `/`


def _fold_path(word: str) -> str:
    """One path with `.`, empty and `dir/..` segments removed (one pass, a stack)."""
    if "/" not in word:
        return word
    out: list[str] = []
    for seg in word.split("/"):
        if seg in ("", "."):
            continue
        if seg == ".." and out and out[-1] != "..":
            out.pop()
        else:
            out.append(seg)
    folded = ("/" if word.startswith("/") else "") + "/".join(out)
    if word.endswith("/") and out:
        folded += "/"
    return folded or "."


def _normalize_paths(text: str) -> str:
    """Path spellings folded for the self-protection rules: backslashes become
    `/`, and `./`, `//` and `dir/..` segments are removed, so
    `.claude/./settings.json`, `.claude\\x\\..\\settings.json` and
    `.claude//settings.json` all read `.claude/settings.json`. Linear in the
    length of the text."""
    return _PATH_WORD.sub(lambda m: _fold_path(m.group()), text.replace("\\", "/"))


@dataclass(frozen=True)
class Match:
    rule_id: str
    description: str
    subject: str  # the text that was matched against (command or tool name)
    self_auth: bool = False


_SHELL_WORD = re.compile(rf"(?:^|[\s;&|(])(?:{_SH}|pwsh|powershell)\b", re.I)


def _feeds_shell(before: str) -> bool:
    """Whether the text before `<<` on its line ends in a shell's simple
    command (`bash <<EOF`): a shell word after the last `|`, `;` or `&`."""
    k = max(before.rfind("|"), before.rfind(";"), before.rfind("&"))
    return _SHELL_WORD.search(before[max(k, 0):]) is not None
# Programs whose quoted argument is itself a shell command line.
_SHELL_STRING_RUNNER = re.compile(
    rf"(?:^|[\s(])(?:{_SH}|su|sudo|ssh|eval|iex|invoke-expression|pwsh|powershell|cmd|wsl|watch|xargs|env|exec"
    r"|(?:docker|podman|kubectl)\s+exec)(?:\.exe)?(?:\s|$)", re.I)
_VIEW_SCAN = re.compile(r"['\";|&\n(]")
_QUOTED_SEPARATORS = str.maketrans(dict.fromkeys(";|&<>\r\n", " "))
_BACKTICKS = re.compile(r"`([^`\n]*)`")


_HEREDOC_SCAN = re.compile(r"['\"#]|<<")
_DQ = re.compile('"')


def _closing_quotes(command: str) -> list[int]:
    """Positions of the `"` characters that can close a double-quoted string:
    those after an even run of backslashes. A run of backslashes cannot
    contain a quote, so whether a `"` is escaped does not depend on where the
    string opened; one pass finds them all."""
    out = []
    for m in _DQ.finditer(command):
        k = m.start()
        j = k
        while j > 0 and command[j - 1] == "\\":
            j -= 1
        if (k - j) % 2 == 0:
            out.append(k)
    return out


def _end_of_double_quote(closers: list[int], i: int) -> int:
    """Index after the `"` that closes the one at ``i`` (a backslash escapes
    the next character), or 0 when it is never closed. ``closers`` is
    ``_closing_quotes`` of the same text, so a long run of unclosed quotes
    is not rescanned from every quote."""
    k = bisect_right(closers, i)
    return closers[k] + 1 if k < len(closers) else 0


_HEREDOC_START = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1[^\n]*\n")
_HEREDOC_END = re.compile(r"[ \t]*([A-Za-z_]\w*)[ \t]*(?:\)|$)")


def _heredocs(command: str) -> list[tuple[int, int, bool]]:
    """(body start, body end, body is a shell script) for each heredoc.

    One pass over the command: a `<<WORD` inside quotes or a `#` comment is
    not a heredoc (`echo "<<EOF"`), and quotes inside a body do not count.
    The terminator is the first later line holding only the word, optionally
    followed by `)`; it is looked up, not searched for, so the pass stays
    linear when a terminator is missing."""
    ends: dict[str, list[int]] = {}
    pos = 0
    for line in command.split("\n"):
        m = _HEREDOC_END.match(line)
        if m:
            ends.setdefault(m.group(1), []).append(pos)
        pos += len(line) + 1
    out: list[tuple[int, int, bool]] = []
    closers = _closing_quotes(command)
    i, n = 0, len(command)
    while True:
        sp = _HEREDOC_SCAN.search(command, i)
        if sp is None:
            return out
        i = sp.start()
        ch = command[i]
        if ch in "'\"":
            j = command.find("'", i + 1) + 1 if ch == "'" else _end_of_double_quote(closers, i)
            if ch == '"' and j > 0 and ("$(" in command[i:j] or "`" in command[i:j]):
                j = i + 1  # a command substitution inside double quotes is a command: read on inside it
            i = j if j > 0 else i + 1  # an unbalanced quote is dropped, as in _structure_view
            continue
        if ch == "#":
            if i == 0 or command[i - 1] in " \t\n;&|(":
                j = command.find("\n", i)
                i = n if j < 0 else j
            else:
                i += 1
            continue
        m = _HEREDOC_START.match(command, i)
        if m:
            starts = ends.get(m.group(2), [])
            k = bisect_left(starts, m.end() + 1)
            if k < len(starts):
                line_start = command.rfind("\n", 0, i) + 1
                out.append((m.end(), starts[k] - 1, _feeds_shell(command[line_start:i])))
                i = starts[k]
                continue
        i += 2


def _drop_data_heredocs(command: str) -> str:
    """The command with heredoc bodies that are data removed (`cat > f <<EOF`);
    a body fed to a shell (`bash <<EOF`) is the script and is kept."""
    parts, last = [], 0
    for start, end, to_shell in _heredocs(command):
        if not to_shell:
            parts.append(command[last:start])
            last = end
    parts.append(command[last:])
    return "".join(parts)


def _structure_view(command: str) -> str:
    """The text the "unresolvable" rules are matched against.

    Like ``normalize_command`` it removes quote characters, but it keeps the
    command's structure honest: separators inside an ordinary quoted argument
    (``sed "s|$A|$B|"``, ``git commit -m "x; $Y"``) are blanked, ``$`` inside
    single quotes is blanked, and heredoc bodies that are data are dropped.
    A quoted argument of a program that runs it as a shell command line
    (``bash -c "..."``, ``eval "..."``, ``ssh host "..."``) is kept as written.
    """
    command = re.sub(r"\\\r?\n", " ", command)
    command = _drop_data_heredocs(command)
    out: list[str] = []
    segment: list[str] = []  # the simple command being read, to spot a runner
    # The segment is checked for a runner incrementally: the text added since
    # the last check plus the end of what was checked, with whitespace runs
    # collapsed (the runner pattern only asks whether there is whitespace), so
    # a long command with many quotes stays linear and nothing is missed.
    checked, tail, runner = 0, "", False
    closers = _closing_quotes(command)
    i, n = 0, len(command)
    while i < n:
        sp = _VIEW_SCAN.search(command, i)
        k = sp.start() if sp else n
        if k > i:
            out.append(command[i:k])
            segment.append(command[i:k])
        if sp is None:
            break
        ch = command[k]
        if ch not in "'\"":
            segment.clear()
            checked, tail, runner = 0, "", False
            out.append(ch)
            i = k + 1
            continue
        j = command.find("'", k + 1) + 1 if ch == "'" else _end_of_double_quote(closers, k)
        if j == 0:
            i = k + 1  # unbalanced quote: drop the character
            continue
        body = command[k + 1:j - 1]
        if not runner:
            window = re.sub(r"\s+", " ", tail + "".join(segment[checked:]))
            runner = _SHELL_STRING_RUNNER.search(window) is not None
            checked = len(segment)
            tail = window if len(window) <= 64 else "x" + window[-64:]
        if not runner:
            body = body.translate(_QUOTED_SEPARATORS)
            if ch == "'":
                body = body.replace("$", " ").replace("`", " ").translate(_LITERAL_BRACKETS)
            else:
                body = _blank_literal_parens(body)
        out.append(body)
        segment.append(body)
        i = j
    view = _BACKTICKS.sub(r"$(\1)", "".join(out))
    return re.sub(r"[ \t]+", " ", re.sub(r"['\"]", "", view))


_UNESCAPE = re.compile(r"\\([^\n])")


_EXPANSION = re.compile(r"\$\{[^{}$\n]*\}|\$\w+")  # no `{` or `$` inside: unclosed `${` runs stay linear


def _has_client(text: str) -> bool:
    """A database client named in ``text``, also with backslash escapes
    removed (`p\\sql`), cmd's `^` escapes removed (`p^sql`), Unicode
    compatibility forms folded (`psq\u217c`), and `${...}` / `$name` cut out
    of words (`p${x}sql`). Erring towards a client only makes the query rules
    read more text."""
    text = unicodedata.normalize("NFKC", _UNESCAPE.sub(r"\1", text)).replace("^", "")
    return _DB_CLIENT.search(text) is not None or _DB_CLIENT.search(_EXPANSION.sub("", text)) is not None


def _command_kind(simple: str) -> str:
    """'client' (runs a database client), 'text' (only carries text) or 'other'.
    Backslash escapes are removed first: `p\\sql` runs psql. A program word
    holding a `$` is never text-only: it could expand to anything."""
    unescaped = _UNESCAPE.sub(r"\1", simple)
    m = _PROGRAM.match(unescaped)
    word = m.group(1) if m else ""
    prog = re.split(r"[/\\]", word)[-1].lower().removesuffix(".exe")
    if prog in _TEXT_ONLY_PROGRAMS and "$" not in word and not _TEXT_PROGRAM_RUNS.search(unescaped):
        return "text"
    return "client" if _has_client(simple) else "other"


_BRACKETS = re.compile(r"\$?[(){}]")
# Quoted (literal) parentheses and braces are written into the structure view
# as these private-use characters, so they never open or close a
# substitution; the query rules get the real characters back.
_LITERAL_BRACKETS = str.maketrans("(){}", "\ue000\ue001\ue002\ue003")
_REAL_BRACKETS = str.maketrans("\ue000\ue001\ue002\ue003", "(){}")


def _blank_literal_parens(body: str) -> str:
    """A double-quoted argument with its literal parentheses and braces
    marked (see _LITERAL_BRACKETS). A `$(` or `${` and what closes it stay
    real, and inside a live `$(...)` everything is command text
    (`"$(iex (Get-Content x))"`)."""
    if not any(c in body for c in "(){}"):
        return body
    out: list[str] = []
    stack: list[str] = []  # "$": a live `$(` / `${`; "L": a bracket inside one; "-": a literal one
    live = 0
    last = 0
    for m in _BRACKETS.finditer(body):
        tok = m.group()
        if tok in ("$(", "${"):
            stack.append("$")
            live += 1
            continue
        if tok[-1] in "({":
            stack.append("L" if live else "-")
            if live:
                continue
            tok = tok[-1]
            start = m.end() - 1
        else:
            kind = stack.pop() if stack else "u"  # an unmatched closer opens nothing: left real
            if kind == "$":
                live -= 1
            if kind != "-":
                continue
            start = m.start()
            if tok[0] == "$":
                tok, start = tok[1:], start + 1
        out += [body[last:start], tok.translate(_LITERAL_BRACKETS)]
        last = start + 1
    out.append(body[last:])
    return "".join(out)


_SUBSTITUTION = re.compile(r"[$<>=@]?\(|\$\{(?=[ \t\n])|[{)}]")


def _substitution_bodies(view: str) -> tuple[list[str], bool]:
    """The contents of every `(...)` and `{...}` in the structure view, each
    with its own nested ones blanked (they are listed separately), so the
    total stays the size of the view. That is: `$(...)` (and backticks,
    which the view turned into `$(`), `<(...)`, `>(...)`, zsh `=(...)`,
    PowerShell `(...)`, `@(...)`, `a(...)` and `{...}`, a subshell, a brace
    group and bash 5.3 `${ ...; }`. Quoted brackets were marked literal by
    the view, so only live ones count. One pass. The flag is False when a
    bracket is left unmatched (the parse is unsure)."""
    bodies: list[str] = []
    balanced = True
    stack: list[tuple[str, int, list[tuple[int, int]]]] = []  # (closer, content start, nested spans)
    for m in _SUBSTITUTION.finditer(view):
        tok = m.group()
        if tok in (")", "}"):
            if not stack or stack[-1][0] != tok:
                balanced = False
                continue
            _, begin, nested = stack.pop()
            parts, last = [], begin
            for a, b in nested:
                parts += [view[last:a], " "]
                last = b
            parts.append(view[last:m.start()])
            bodies.append("".join(parts))
            if stack:
                stack[-1][2].append((begin, m.end()))
            continue
        stack.append(("}" if tok.endswith("{") else ")", m.end(), []))
    return bodies, balanced and not stack


def _pipelines(line: str, base: list[str], client: list[str], powershell: bool = False) -> bool:
    """Sort the simple commands of one command line into ``base`` (may hold a
    query) and ``client`` (runs a database client). True when a client reads
    a file or redirect, so anything on the line may be its query."""
    # In PowerShell a lone `&` is the call operator, not a separator.
    for pipeline in re.split(r"\|\||&&|[;\n]" if powershell else r"\|\||&&|[;&\n]", line.replace("|&", "|")):
        simples = pipeline.split("|")
        kinds = [_command_kind(s) for s in simples]
        if "client" in kinds[1:]:
            client.append(normalize_command(pipeline))  # text piped into a client is a query
            continue
        for simple, kind in zip(simples, kinds):
            if kind == "client":
                if _CLIENT_READS_INPUT.search(simple):
                    return True
                client.append(normalize_command(simple))
            elif kind == "other":
                base.append(normalize_command(simple))
    return False


# Where the structure view's quote and bracket tracking may be wrong: then the
# query rules read the whole line, as main does, instead of trusting the
# text-only and heredoc-body exemptions.
_UNSURE = re.compile(r"\$\(|`|[<>=]\(|\$\{|\$'|\\[\"'(){}]")


def _unsure(text: str) -> bool:
    return _UNSURE.search(text) is not None


# A program that is computed or that runs another command line: PowerShell
# `&` / `.` before anything but a plain word, `iex`, `eval`, `source`, `xargs`,
# a variable as the program, `sh -c`, `cmd /c`, `powershell -c`.
_COMPUTED = (
    re.compile(r"(?<![&>\d])&(?!&)\s*(?![A-Za-z_][\w.-]*(?:\s|$|[;|)]))\S"
               r"|(?:^|[\s;|&(])\.\s+(?![A-Za-z_][\w.-]*(?:\s|$|[;|)]))\S"
               r"|\b(?:iex|invoke-expression|eval|source|xargs)\b"
               r"|(?:^|[;|&\n({])\s*\$[\w{(]"
               rf"|\b{_SH}\s+(?:-\w+\s+)*-\w*c\b|\bcmd(?:\.exe)?\s+(?:/\w\s+)*/[ck]\b", re.IGNORECASE),
    _FirstStart(r"\b(?:powershell|pwsh)(?:\.exe)?\b",
                r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;|&\n]*\s-(?:c|command|e|ec|enc\w*)\b", "[;|&\n]"),
)


def _computed_program(text: str) -> bool:
    return any(rx.search(text) for rx in _COMPUTED)


def _query_texts(text: str, norm: str, view: str | None, powershell: bool = False) -> tuple[list[str], list[str]]:
    """(texts for the query rules, texts that may also use the client-only
    rules). ``view`` is the structure view of a shell command line, or None
    for scripts, file content and MCP arguments (all the text counts).

    The exemptions (text-only programs, heredoc bodies that are data) apply
    only where the parse is sure; otherwise all the text counts, as on main.
    Where they apply, the command line is sorted exactly as written and the
    contents of each substitution are sorted again on top of that."""
    client_anywhere = _has_client(norm)
    full = [norm], ([norm] if client_anywhere else [])
    # The exemptions only ever apply where no database client is named and no
    # program is computed: SQL written earlier on the line can reach a client
    # through a file, a variable or git config (`echo ... > q.sql; cat q.sql
    # | psql`), and a computed program can be one (`| & ("ps" + "ql")`).
    if view is None or client_anywhere or _unsure(text) or _computed_program(text):
        return full
    bodies, balanced = _substitution_bodies(view)
    if not balanced:
        return full
    base: list[str] = []
    client: list[str] = []
    for line in [view] + bodies:
        if _pipelines(line.translate(_REAL_BRACKETS), base, client, powershell):
            return full  # `psql -f f.sql`: anything on the line may be the query
    return base + client, client


def _query_match(text: str, norm: str, view: str | None, powershell: bool = False) -> Match | None:
    """The query-language rules, applied only where a query can be (see QUERY_RULES)."""
    texts, client_texts = _query_texts(text, norm, view, powershell)
    for rules, ts in ((QUERY_RULES, texts), (CLIENT_QUERY_RULES, client_texts)):
        for rule in rules:
            for t in ts:
                if rule.pattern.search(t):
                    return Match(rule.rule_id, rule.description, text)
    return None


def _too_long(subject: str, size: int, limit: int, what: str) -> Match:
    return Match("guard.too-long",
                 f"{what} too long to check safely ({size} chars > {limit}); split it or write it in parts", subject)


def _first_match(text: str, *, include_self_auth: bool = True, shell: str | None = None) -> Match | None:
    """``shell`` is the shell tool's name when ``text`` is a command line typed
    into a shell; only then are the variable-indirection rules applied."""
    norm = normalize_command(text)
    if include_self_auth:
        paths = _normalize_paths(norm)
        for rule in SELF_AUTH_RULES:
            if rule.pattern.search(paths):
                if rule.rule_id == "guard.self-disable" and _READ_ONLY_PREFIX.match(paths):
                    continue
                return Match(rule.rule_id, rule.description, text, self_auth=True)
    for rule in SHELL_RULES:
        if rule.pattern.search(norm):
            return Match(rule.rule_id, rule.description, text)
    # The structure view is needed for redirects, shell command lines and downloads.
    need_view = shell is not None or ">" in text or _PREFILTER_REMOTE.search(text) is not None
    view = _structure_view(text) if need_view else ""
    unsure = _unsure(text)
    for rule in REDIRECT_RULES:
        if (need_view and rule.pattern.search(view)) or (unsure and rule.pattern.search(norm)):
            return Match(rule.rule_id, rule.description, text)
    hit = _query_match(text, norm, view if shell is not None else None, shell == "PowerShell")
    if hit is not None:
        return hit
    if shell is None and not _PREFILTER_REMOTE.search(text):
        return None
    rules = REMOTE_SCRIPT_RULES
    if shell is not None:
        rules += INDIRECT_RULES + (() if shell == "PowerShell" else POSIX_INDIRECT_RULES)
    views = [view, view.translate(_REAL_BRACKETS)] if unsure else [view]
    for rule in rules:
        if any(rule.pattern.search(v) for v in views):
            return Match(rule.rule_id, rule.description, text)
    return None


def _scan_script_files(command: str, cwd: str | os.PathLike | None) -> Match | None:
    """If the command runs a script file that exists, scan the script's content too."""
    if cwd is None:
        return None
    names = [m.group(1) for m in _SCRIPT_RUN.finditer(command)]
    for line in command.split("\n"):
        for prog, arg in _SCRIPT_RUN_DB:
            p = prog.search(line)
            if p:
                names += [m.group(1) for m in arg.finditer(line, p.end())]
    for name in names:
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
        if len(command) > MAX_COMMAND_CHARS:
            return _too_long(command, len(command), MAX_COMMAND_CHARS, "command")
        return _first_match(command, shell=tool_name) or _scan_script_files(command, cwd)
    if tool_name in _FILE_TOOLS_WITH_PATH:
        target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm_target = _normalize_paths(normalize_command(target))
        for rule in SELF_AUTH_RULES[1:]:
            if rule.pattern.search(norm_target) and (tool_name in _WRITE_TOOLS or rule.rule_id == "guard.key-access"):
                return Match(rule.rule_id, rule.description, target, self_auth=True)
        if tool_name in _WRITE_TOOLS and target.lower().endswith(_SCRIPT_EXT):
            body = " ".join(str(tool_input.get(k) or "") for k in ("content", "new_string", "new_source"))
            for e in tool_input.get("edits") or []:
                if isinstance(e, dict):
                    body += " " + str(e.get("new_string") or "")
            if len(body) > MAX_CONTENT_CHARS:
                return _too_long(target, len(body), MAX_CONTENT_CHARS, "content")
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
        texts = _string_values(tool_input)
        total = sum(len(t) for t in texts)
        if total > MAX_CONTENT_CHARS:
            return _too_long(subject, total, MAX_CONTENT_CHARS, "MCP arguments")
        for text in texts:
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
    if m.rule_id == "guard.too-long":
        # Not a destructive command, so a backup precondition is not the remedy.
        return Decision("deny", m.rule_id, None, f"perathos guard: blocked: {m.description}.")
    hint = ('A person must first run, outside this agent session:\n'
            '  perathos precondition add --scope "<target name in the command>" --check "<command that '
            'proves a restorable backup exists>"\n'
            'then retry. The check must exit 0.')
    if "unresolvable." in m.rule_id:
        hint = ("If you know what this runs, write the command out literally and retry; the guard can then "
                "judge it.\nOtherwise: " + hint)
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
