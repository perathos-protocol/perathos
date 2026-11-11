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
# Because quotes are gone, a rule cannot use a quote to find where an argument
# ends: `psql -c "DELETE FROM t" -h db` arrives as `psql -c DELETE FROM t -h db`.

# Options before a subcommand or argument, each with an optional value:
# `terraform -chdir=infra destroy`, `kubectl delete -n prod pvc`, `git -C repo reset`.
_OPTS = r"(?:-[^\s;&|]+\s+(?:(?!-)[^\s;&|]+\s+)?)*"
# Any words of the same simple command (no separator crossed).
_ARGS = r"(?:[^\s;&|]+\s+)*?"
# The rest of the same simple command.
_REST = r"[^;&|\n]*"
# A redirect target with a database-file extension. `.csv` and `.sql` are left
# out on purpose: `script > out.csv` is ordinary output, and `pg_dump db >
# backup.sql` makes a backup.
_DATA_FILE = r"[^\s;&|<>]+\.(?:db|sqlite3?|duckdb|mdb|accdb|parquet)(?=\s|$|[;&|)])"
_K8S_STATEFUL = r"(?:ns|namespaces?|pv|pvc|persistentvolume\w*|statefulsets?|sts|deployments?|deploy|all)\b"

SHELL_RULES: tuple[Rule, ...] = (
    _r("fs.rm-recursive",
       r"\brm\s+(-\S+\s+)*(-[a-z]*r|--recursive\b)|\brm\s+(-\S+\s+)*-[a-z]*f[a-z]*r",
       "recursive delete"),
    # cmd.exe takes switches anywhere on the line: `rmdir data /s /q`
    _r("fs.win-delete",
       rf"(^|[\s;&|(])(del|erase)\s+{_ARGS}/[sq]\b|(^|[\s;&|(])(rd|rmdir)\s+{_ARGS}/s\b|(^|[\s;&|(])format\s+[a-z]:",
       "Windows recursive or quiet delete"),
    _r("fs.ps-delete",
       r"\b(remove-item|ri|del|erase|rd|rmdir|rm)\s+(\S+\s+)*-(r|recurse|rec|force)\b",
       "PowerShell recursive delete"),
    _r("fs.find-delete", r"\bfind\b.*\s(-delete\b|-exec\s+rm\b)", "find -delete"),
    _r("fs.truncate-or-overwrite",
       r"\btruncate\s+(-s\s*0|--size[= ]0)\b|\bdd\s+.*\bof=(?!/dev/null)|\bshred\b|\bmv\s+\S+\s+/dev/null|(^|[;&|])\s*:\s*>\s*\S",
       "file truncated, overwritten or shredded"),
    # `> file` with no command, `cp /dev/null file`, `cat /dev/null > file` and
    # PowerShell `Clear-Content` empty any file. An ordinary `cmd > file` is
    # flagged only when it would overwrite a database file (``_DATA_FILE``).
    _r("fs.redirect-truncate",
       r"(?:^|[;(]|&&|\|\|)\s*>\|?\s*[^\s>&|;]|\bcp\s+(?:-\S+\s+)*/dev/null\s|\bcat\s+/dev/null\s*>(?!>)"
       rf"|\bclear-content\b|(?<![>\d])>(?!>)\|?\s*{_DATA_FILE}",
       "file emptied by a redirect"),
    _r("fs.interpreter-delete",
       r"shutil\)?\.rmtree|\.(rm|rmSync|rmdir|rmdirSync|promises\.rm)\s*\(.*recursive|\brimraf\b|FileUtils\.rm_rf|\bos\.(remove|unlink|rmdir|removedirs)\s*\(.*\*",
       "delete through an interpreter one-liner"),
    # `from shutil import rmtree; rmtree(p)`, `import shutil as s; s.rmtree(p)`
    _r("fs.python-rmtree",
       r"\bfrom\s+shutil\s+import\b[^\n;]*\brmtree\b(?:\s+as\s+(?P<fn>\w+))?[\s\S]*?\b(?:(?P=fn)|rmtree)\s*\("
       r"|\bimport\s+shutil\s+as\s+(?P<mod>\w+)\b[\s\S]*?\b(?P=mod)\.rmtree\s*\(",
       "delete through an interpreter one-liner (rmtree imported by name)"),
    _r("fs.robocopy-mirror", rf"\brobocopy\b{_REST}\s/(mir|purge)\b",
       "robocopy /MIR or /PURGE (deletes files missing from the source)"),
    _r("fs.ps-format", r"\b(format-volume|clear-disk|remove-partition)\b", "PowerShell volume format or disk wipe"),
    # `checkout <tree> -- <paths>` and `checkout <tree> .` overwrite the work
    # tree; `restore` does too unless it only unstages (`--staged`, no `--worktree`).
    _r("git.destructive",
       rf"\bgit\s+{_OPTS}(reset\s+{_ARGS}--hard\b|clean\s+-\S*[fd]|checkout\s+{_ARGS}(-f\b|--force(?![\w-])|--(\s|$)|\.(\s|$))"
       rf"|restore\b(?={_REST}\s(\.|:/|--)(\s|$))(?:(?={_REST}\s(--worktree\b|(?-i:-W)\b))|(?!{_REST}\s(--staged\b|(?-i:-S)\b)))"
       rf"|switch\s+{_ARGS}(-f\b|--force(?![\w-])|--discard-changes\b)"
       r"|branch\s+(?-i:-D)\b|stash\s+(drop|clear)|filter-branch|reflog\s+expire|update-ref\s+-d)",
       "git command that discards work"),
    _r("git.force-push-main", r"\bgit\s+push\b.*(--force\b|-f\b|--mirror\b).*\b(main|master|prod|production)\b|\bgit\s+push\s+--mirror\b",
       "force push to a main branch"),
    _r("git.push-main-rewrite",
       r"\bgit\s+push\b.*\s(\+\S*\b(main|master|prod|production)\b|:(refs/heads/)?(main|master|prod|production)\b)"
       r"|\bgit\s+push\b.*(--delete\b|\s-d\b).*\b(main|master|prod|production)\b",
       "forced overwrite or delete of a main branch on the remote"),
    _r("git.repo-delete", r"\bgh\s+repo\s+delete\b", "GitHub repository delete"),
    _r("fs.mkfs", r"(^|[\s;&|(])mkfs(\.\w+)?\s", "filesystem format"),
    _r("fs.rsync-delete", r"\brsync\b.*\s--(delete(-\w+)*|remove-source-files)\b", "rsync that deletes files"),
    _r("sql.drop", r"\bdrop\s+(database|schema|table)\b", "SQL DROP"),
    _r("sql.truncate", r"\btruncate\s+(table\s+)?[\w.$\[\]]+", "SQL TRUNCATE"),
    # The statement ends at `;`, a newline, `)`, a shell separator or the next
    # shell option (`-h db`). An alias may follow the table; a WHERE may not.
    _r("sql.delete-all",
       r"\bdelete\s+from\s+[\w.$\[\]]+(?:\s+(?:as\s+)?(?!where\b)\w+)?(?!\s*where\b)\s*(?:$|[;)|&\n]|-{1,2}[a-z]|--\s)",
       "SQL DELETE without WHERE"),
    _r("sql.alter-drop",
       r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?[\w.$\[\]]+\s+(?:[^;\n]*?,\s*)?drop\s+"
       r"(?:column\b|constraint\b|(?!index\b|key\b|primary\b|foreign\b|default\b|check\b|trigger\b|if\b)\w+)",
       "SQL ALTER TABLE ... DROP COLUMN / CONSTRAINT"),
    _r("db.dropdb", r"\bdropdb\b", "PostgreSQL dropdb"),
    _r("db.mysqladmin-drop", rf"\bmysqladmin\b{_REST}\sdrop\b", "mysqladmin drop"),
    _r("db.redis-flush", r"\bflush(all|db)\b", "Redis FLUSHALL / FLUSHDB"),
    _r("db.mongo-drop", r"\.drop(database)?\s*\(", "MongoDB drop"),
    _r("db.mongo-delete-all", r"\.(deleteMany|remove)\s*\(\s*\{\s*\}\s*[,)]|\.deleteMany\s*\(\s*\)",
       "MongoDB delete of every document"),
    _r("db.migrate-reset",
       rf"\b(prisma\s+{_OPTS}migrate\s+{_OPTS}reset|rails\s+db:(drop|reset)|supabase\s+db\s+reset|heroku\s+pg:reset)\b",
       "database reset"),
    _r("db.prisma-force-reset", rf"\bprisma\s+{_OPTS}db\s+push\b{_REST}\s--(force-reset|accept-data-loss)\b",
       "prisma db push that drops data"),
    _r("db.django-flush", rf"\b(manage\.py|django-admin)\s+{_OPTS}(flush|reset_db)\b", "Django flush (deletes every row)"),
    _r("iac.terraform-destroy", rf"\bterraform\s+{_OPTS}(destroy|apply\b{_REST}\s-destroy)\b", "terraform destroy"),
    _r("iac.tofu-destroy", rf"\btofu\s+{_OPTS}(destroy|apply\b{_REST}\s-destroy)\b", "OpenTofu destroy"),
    _r("iac.terragrunt-destroy",
       rf"\bterragrunt\s+{_OPTS}(?:(?:run-all|run)\s+{_OPTS}(?:--\s+)?)?(destroy|apply\b{_REST}\s-destroy)\b",
       "terragrunt destroy"),
    _r("iac.pulumi-destroy", r"\bpulumi\s+destroy\b", "pulumi destroy"),
    _r("k8s.delete", rf"\bkubectl\s+{_OPTS}delete\s+{_OPTS}{_K8S_STATEFUL}",
       "kubectl delete of stateful resources"),
    _r("k8s.helm-uninstall", r"\bhelm\s+(uninstall|delete)\b", "helm uninstall"),
    _r("cloud.aws-delete",
       rf"\baws\s+{_OPTS}(s3\s+rb\b|s3\s+rm\b{_REST}--recursive|rds\s+delete-|dynamodb\s+delete-table|ec2\s+delete-(volume|snapshot)|backup\s+delete-|s3api\s+delete-bucket\b|cloudformation\s+delete-stack\b)",
       "AWS delete of storage or backups"),
    _r("cloud.aws-s3-sync-delete", rf"\baws\s+{_OPTS}s3\s+sync\b{_REST}\s--delete\b",
       "aws s3 sync --delete (deletes objects missing from the source)"),
    _r("cloud.gcloud-delete",
       rf"\bgcloud\s+{_REST}\b(sql\s+(instances|databases|backups)|compute\s+(disks|snapshots)|storage\s+buckets"
       rf"|firestore\s+databases|spanner\s+(instances|databases)|filestore\s+(instances|backups)){_REST}\sdelete\b"
       rf"|\bgcloud\s+{_REST}\bstorage\s+rm\b|\bgcloud\s+{_REST}\bprojects\s+delete\b",
       "Google Cloud delete of storage or backups"),
    _r("cloud.gsutil-delete", rf"\bgsutil\s+{_OPTS}(rb\b|rm\b{_REST}\s-([a-z]*r[a-z]*|-recursive)\b)",
       "gsutil bucket remove or recursive delete"),
    _r("cloud.rclone-delete", rf"\brclone\s+{_OPTS}(purge|delete)\b", "rclone purge / delete"),
    _r("cloud.az-delete", r"\baz\s+(sql|storage|disk|snapshot|backup|cosmosdb|group)\b.*\bdelete\b", "Azure delete of storage or backups"),
    _r("paas.railway", r"\brailway\s+(down|volume\s+delete|delete)\b", "Railway delete"),
    _r("paas.vercel", r"\bvercel\s+(remove|rm)\b", "Vercel remove"),
    _r("paas.fly", r"\bfly(ctl)?\s+(volumes?\s+(destroy|delete)|apps?\s+destroy|postgres\s+destroy)\b", "Fly destroy"),
    _r("paas.neon", r"\bneon(ctl)?\s+(branches?|projects?|databases?)\s+delete\b", "Neon delete"),
    _r("paas.firebase", rf"\bfirebase\s+{_OPTS}(firestore:delete|database:remove)\b", "Firebase data delete"),
    _r("paas.heroku", rf"\bheroku\s+{_OPTS}(apps:destroy|destroy|pg:backups:delete|addons:destroy)\b", "Heroku destroy"),
    _r("docker.volume",
       r"\bdocker\s+(volume\s+(rm|prune)|system\s+prune\b.*--volumes)|\bdocker([ -])compose\b.*\sdown\b.*\s(-v\b|--volumes\b)",
       "Docker volume delete"),
    # podman and nerdctl take docker's volume commands; `system reset` wipes all storage
    _r("container.volume",
       r"\b(podman|nerdctl)\s+(volume\s+(rm|prune)|system\s+prune\b.*--volumes|system\s+reset\b)"
       r"|\b(podman|nerdctl)([ -])compose\b.*\sdown\b.*\s(-v\b|--volumes\b)",
       "podman / nerdctl volume delete"),
)

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
       r"(?:(?:sudo|exec|command|builtin|nohup|time|env|xargs|nice|watch|timeout\s+[\d.]+\w?)\s+)*(?:[a-z_]\w*=\S*\s+)*")
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

REMOTE_SCRIPT_RULES: tuple[Rule, ...] = (
    _r("unresolvable.remote-script", rf"\b{_DL}\b[^;&\n]*{_STDIN_SINK}",
       "download piped into an interpreter (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"(?:\b(?:{_INTERP}|source)|(?:^|[\s;&|(])\.)\s+(?:-\S+\s+)*<?\s*<\(\s*(?:sudo\s+)?{_DL}\b",
       "download substituted into an interpreter (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"\b(?:eval|iex|invoke-expression)\b[^;|\n]*\b{_DL}\b|\s(?:-\w*c|-e|-r|-command|/c)\s+\$\(\s*{_DL}\b"
       rf"|{_CP}\$\(\s*{_DL}\b|\[scriptblock\]::create\([^\n]*\b{_DL}\b",
       "download evaluated as a command (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"\b{_DL}\b[^\n;&|]*?[/\s=]([\w-][\w.-]*)(?=[\s;&])[^\n;&|]*(?:&&|;|\n)(?:[\s\S]*?(?:&&|;|\n))??\s*"
       rf"(?:sudo\s+)?(?:(?:{_INTERP}|source)\s+(?:-\S+\s+)*|&\s*)?(?:[\w.~/\\-]*[/\\])?\1{_WORD_END}",
       "download saved and then run (the guard cannot see what it would run)"),
)

INDIRECT_RULES: tuple[Rule, ...] = (
    _r("unresolvable.indirect", rf"{_CP}\$\((?![^()\n]*\)[/\\][^\s$`;&|()]*[^\s$`;&|()/\\](?:\s|$|[;&|)]))",
       "command produced by a command substitution (the guard cannot tell what would run)"),
    _r("unresolvable.indirect", rf"{_CP}eval\s+(?!{_EVAL_OK})[^;&|\n]*\$",
       "eval of a variable or substitution (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       rf"\b(?:{_INTERP}|psql|mysql|su|wsl)\s+(?:[^\s;&|]+\s+)*?(?:-\w*c|-e|-r|-command|--command|/c|/k)\s+"
       r"(?:\$[\w{(]|[%!]\w+[%!])|\s-exec(?:dir)?\s+\$[\w{(]|\btrap\s+\$[\w{(]",
       "command string held in a variable (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       rf"{_CP}(?:{_INTERP}|source|\.)\s+(?:-(?!c\b|e\b|r\b|command\b)\S+\s+)*{_VAR}{_WORD_END}",
       "script whose path is held in a variable (the guard cannot read it)"),
    _r("unresolvable.indirect", _STDIN_SINK,
       "text piped into an interpreter (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       rf"\b{_SH}\b[^;&|\n]*<<<[^;&|\n]*\$|(?:\b(?:{_SH}|source)|(?:^|[\s;&|(])\.)\s+(?:-\S+\s+)*<?\s*<\(",
       "substitution fed to a shell as its script (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       r"(?<![>\d&])&\s*\$[\w{(]|\b(?:iex|invoke-expression)\s+(?:-command\s+)?[$(@]"
       r"|\[scriptblock\]::create\([^)\n]*\$|\b(?:start-process|saps)\s+(?:-filepath\s+)?\$"
       r"|\b(?:invoke-command|icm)\b[^;|\n]*-scriptblock\s+\$",
       "PowerShell call of a variable or expression (the guard cannot tell what would run)"),
    _r("unresolvable.indirect", r"\b(?:powershell|pwsh)(?:\.exe)?\b[^;|&\n]*\s-(?:e|ec|en\w*)\s+[a-z0-9+/=]{8,}",
       "PowerShell encoded command (the guard cannot tell what would run)"),
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


_DOT_SEGMENT = re.compile(r"(?<=/)\.(?:/|(?=\s|$))")
_PARENT_SEGMENT = re.compile(r"(?<![^\s/=:])(?!\.\.(?:/|\s|$))[^/\s=:]+/\.\.(?:/|(?=\s|$))")


def _normalize_paths(text: str) -> str:
    """Path spellings folded for the self-protection rules: backslashes become
    `/`, and `./`, `//` and `dir/..` segments are removed, so
    `.claude/./settings.json`, `.claude\\x\\..\\settings.json` and
    `.claude//settings.json` all read `.claude/settings.json`."""
    text = text.replace("\\", "/")
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"/{2,}", "/", _PARENT_SEGMENT.sub("", _DOT_SEGMENT.sub("", text)))
    return text


@dataclass(frozen=True)
class Match:
    rule_id: str
    description: str
    subject: str  # the text that was matched against (command or tool name)
    self_auth: bool = False


_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1[^\n]*\n(.*?)\n[ \t]*\2[ \t]*(?=\n|$|\))", re.S)
_HEREDOC_TO_SHELL = re.compile(rf"(?:^|[\s;&|(])(?:{_SH}|pwsh|powershell)\b[^|;&]*$", re.I)
# Programs whose quoted argument is itself a shell command line.
_SHELL_STRING_RUNNER = re.compile(
    rf"(?:^|[\s(])(?:{_SH}|su|sudo|ssh|eval|iex|invoke-expression|pwsh|powershell|cmd|wsl|watch|xargs|env|exec"
    r"|(?:docker|podman|kubectl)\s+exec)(?:\.exe)?(?:\s|$)", re.I)
_QUOTED_SEPARATORS = str.maketrans(dict.fromkeys(";|&<>\r\n", " "))
_BACKTICKS = re.compile(r"`([^`\n]*)`")


def _drop_heredoc_body(m: re.Match) -> str:
    line_start = m.string.rfind("\n", 0, m.start()) + 1
    if _HEREDOC_TO_SHELL.search(m.string[line_start:m.start()]):
        return m.group(0)  # `bash <<EOF`: the body is the script
    return m.string[m.start():m.start(3)] + m.string[m.end(3):m.end()]


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
    command = _HEREDOC.sub(_drop_heredoc_body, command)
    out: list[str] = []
    segment: list[str] = []  # the simple command being read, to spot a runner
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if ch in "'\"":
            j = i + 1
            while j < n and command[j] != ch:
                if ch == '"' and command[j] == "\\" and j + 1 < n:
                    j += 1
                j += 1
            if j < n:
                body = command[i + 1:j]
                if not _SHELL_STRING_RUNNER.search("".join(segment)):
                    body = body.translate(_QUOTED_SEPARATORS)
                    if ch == "'":
                        body = body.replace("$", " ").replace("`", " ")
                out.append(body)
                segment.append(body)
                i = j + 1
                continue
            i += 1  # unbalanced quote: drop the character
            continue
        if ch in ";|&\n(":
            segment.clear()
        else:
            segment.append(ch)
        out.append(ch)
        i += 1
    view = _BACKTICKS.sub(r"$(\1)", "".join(out))
    return re.sub(r"[ \t]+", " ", re.sub(r"['\"]", "", view))


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
    if shell is None and not _PREFILTER_REMOTE.search(text):
        return None
    view = _structure_view(text)
    rules = REMOTE_SCRIPT_RULES
    if shell is not None:
        rules += INDIRECT_RULES + (() if shell == "PowerShell" else POSIX_INDIRECT_RULES)
    for rule in rules:
        if rule.pattern.search(view):
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
