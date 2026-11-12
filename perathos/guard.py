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
from bisect import bisect_left
from dataclasses import replace
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


class _RmtreeImportedByName:
    """`from shutil import rmtree [as r]` (or `import *`) or `import shutil as
    s`, followed anywhere later by a call through that name. A regex with a
    lazy gap would be quadratic on repeated imports; this looks up each
    distinct name once (at most 32 of them)."""

    _IMPORT = re.compile(r"\bfrom\s+shutil\s+import\b([^\n;]{0,256})|\bimport\s+shutil\s+as\s+(\w+)\b", re.IGNORECASE)
    _NAMED = re.compile(r"\brmtree\b(?:\s+as\s+(\w+))?|(\*)", re.IGNORECASE)

    def search(self, text: str) -> re.Match | None:
        seen: set[str] = set()
        for m in self._IMPORT.finditer(text):
            if m.group(2) is not None:
                call = rf"\b{re.escape(m.group(2))}\.rmtree\s*\("
            else:
                named = self._NAMED.search(m.group(1))
                if named is None:
                    continue
                call = rf"\b{re.escape(named.group(1) or 'rmtree')}\s*\("
            if call in seen:
                continue
            seen.add(call)
            hit = re.compile(call, re.IGNORECASE).search(text, m.end())
            if hit is not None or len(seen) >= 32:
                return hit
        return None


# Shell / CLI commands that can destroy data or the means to recover it.
# Matched against a normalised copy of the command (quotes removed, SQL
# comments collapsed), so `r""m -rf`, `k''eys` and `DROP/**/TABLE` match.
# Because quotes are gone, a rule cannot use a quote to find where an argument
# ends: `psql -c "DELETE FROM t" -h db` arrives as `psql -c DELETE FROM t -h db`.
#
# Repetitions are bounded ({0,N}) so a long command made of repeated keywords
# cannot make a rule take seconds; long input is matched in pieces (see
# CHUNK_CHARS) and only input over a hard cap is denied unmatched.

# Options before a subcommand or argument, each with an optional value:
# `terraform -chdir=infra destroy`, `aws --profile p s3 rb`, `git -C repo reset`.
_OPTS = r"(?:-[^\s;&|]+\s+(?:(?!-)[^\s;&|]+\s+)?){0,32}"
# Any words of the same simple command (no separator crossed).
_ARGS = r"(?:[^\s;&|]+\s+){0,64}?"
# The rest of the same simple command, and the rest of the line.
_REST = r"[^;&|\n]{0,1024}"
_ANY = r"[^\n]{0,1024}"
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
_K8S_OPTS = rf"(?:{_K8S_VALUE_OPT}\s+[^\s;&|]+\s+|(?!{_K8S_VALUE_OPT}\s)-[^\s;&|]+\s+){{0,32}}"
_K8S_STATEFUL = r"(?:ns|namespaces?|pv|pvc|persistentvolume\w*|statefulsets?|sts|deployments?|deploy|all)(?=$|[\s/,.;&|)])"
# A git pathspec for the whole work tree: `.`, `./`, `:/`, `*`. (`--` with no
# pathspec after it is a no-op for `checkout` and an error for `restore`.)
_WHOLE_TREE = rf"(?::/\.?|\./?|\.?\*){_END}"

SHELL_RULES: tuple[Rule, ...] = (
    _r("fs.rm-recursive",
       r"\brm\s+(-\S+\s+){0,32}(-[a-z]*r|--recursive\b)|\brm\s+(-\S+\s+){0,32}-[a-z]*f[a-z]*r",
       "recursive delete"),
    # cmd.exe takes switches anywhere on the line: `rmdir data /s /q`
    _r("fs.win-delete",
       rf"(^|[\s;&|(])(del|erase)\s+{_ARGS}/[sq]\b|(^|[\s;&|(])(rd|rmdir)\s+{_ARGS}/s\b|(^|[\s;&|(])format\s+[a-z]:",
       "Windows recursive or quiet delete"),
    _r("fs.ps-delete",
       r"\b(remove-item|ri|del|erase|rd|rmdir|rm)\s+(\S+\s+){0,64}-(r|recurse|rec|force)\b",
       "PowerShell recursive delete"),
    _r("fs.find-delete", rf"\bfind\b{_ANY}\s(-delete\b|-exec\s+rm\b)", "find -delete"),
    _r("fs.truncate-or-overwrite",
       rf"\btruncate\s+(-s\s*0|--size[= ]0)\b|\bdd\s+{_ANY}\bof=(?!/dev/null)|\bshred\b|\bmv\s+\S+\s+/dev/null",
       "file truncated, overwritten or shredded"),
    # `cp /dev/null file`, `cat /dev/null > file` and PowerShell `Clear-Content`
    # empty any file. (Redirects are judged on the structure view: REDIRECT_RULES.)
    _r("fs.redirect-truncate",
       rf"\bcp\s+(?:-\S+\s+){{0,8}}/dev/null\s+{_NOT_A_FILE}\S|\bcat\s+/dev/null\s*>(?!>)\|?\s*{_NOT_A_FILE}\S|\bclear-content\b",
       "file emptied by a redirect"),
    _r("fs.interpreter-delete",
       rf"shutil\)?\.rmtree|\.(rm|rmSync|rmdir|rmdirSync|promises\.rm)\s*\({_ANY}recursive|\brimraf\b|FileUtils\.rm_rf|\bos\.(remove|unlink|rmdir|removedirs)\s*\({_ANY}\*",
       "delete through an interpreter one-liner"),
    # `from shutil import rmtree; rmtree(p)`, `... import rmtree as r; r(p)`,
    # `from shutil import *; rmtree(p)`, `import shutil as s; s.rmtree(p)`
    Rule("fs.python-rmtree", _RmtreeImportedByName(),  # type: ignore[arg-type]
         "delete through an interpreter one-liner (rmtree imported by name)"),
    _r("fs.robocopy-mirror", rf"\brobocopy\b{_REST}\s/(mir|purge)\b",
       "robocopy /MIR or /PURGE (deletes files missing from the source)"),
    _r("fs.ps-format", r"\b(format-volume|clear-disk|remove-partition)\b", "PowerShell volume format or disk wipe"),
    # Discarding work in the whole tree is flagged: `checkout -f`, `checkout
    # [<tree>] [--] .`, `restore .` / `restore :/` unless it only unstages
    # (`--staged` without `--worktree`). Named files or directories
    # (`checkout -- a.py`, `checkout feature -- ci.yml`, `restore src/`) are not.
    _r("git.destructive",
       rf"\bgit\s+{_OPTS}(reset\s+{_ARGS}--hard\b|clean\s+-\S*[fd]"
       rf"|checkout\s+{_ARGS}(-f\b|--force(?![\w-])|(--\s+)?{_WHOLE_TREE})"
       rf"|restore\b(?={_REST}\s{_WHOLE_TREE})"
       rf"(?:(?={_REST}\s(--worktree\b|(?-i:-[A-Za-z]*W[A-Za-z]*)\b))|(?!{_REST}\s(--staged\b|(?-i:-[A-Za-z]*S[A-Za-z]*)\b)))"
       rf"|switch\s+{_ARGS}(-f\b|--force(?![\w-])|--discard-changes\b)"
       r"|branch\s+(?-i:-D)\b|stash\s+(drop|clear)|filter-branch|reflog\s+expire|update-ref\s+-d)",
       "git command that discards work"),
    _r("git.force-push-main",
       rf"\bgit\s+push\b{_ANY}(--force\b|-f\b|--mirror\b){_ANY}\b(main|master|prod|production)\b|\bgit\s+push\s+--mirror\b",
       "force push to a main branch"),
    _r("git.push-main-rewrite",
       rf"\bgit\s+push\b{_ANY}\s(\+\S*\b(main|master|prod|production)\b|:(refs/heads/)?(main|master|prod|production)\b)"
       rf"|\bgit\s+push\b{_ANY}(--delete\b|\s-d\b){_ANY}\b(main|master|prod|production)\b",
       "forced overwrite or delete of a main branch on the remote"),
    _r("git.repo-delete", r"\bgh\s+repo\s+delete\b", "GitHub repository delete"),
    _r("fs.mkfs", r"(^|[\s;&|(])mkfs(\.\w+)?\s", "filesystem format"),
    _r("fs.rsync-delete", rf"\brsync\b{_ANY}\s--(delete(-\w+)*|remove-source-files)\b", "rsync that deletes files"),
    _r("db.dropdb", r"\bdropdb\b", "PostgreSQL dropdb"),
    _r("db.mysqladmin-drop", rf"\bmysqladmin\b{_REST}\sdrop\b", "mysqladmin drop"),
    _r("db.migrate-reset",
       rf"\b(prisma\s+{_OPTS}migrate\s+{_OPTS}reset|rails\s+db:(drop|reset)|supabase\s+db\s+reset|heroku\s+pg:reset)\b",
       "database reset"),
    _r("db.prisma-force-reset", rf"\bprisma\s+{_OPTS}db\s+push\b{_REST}\s--(force-reset|accept-data-loss)\b",
       "prisma db push that drops data"),
    _r("db.django-flush", rf"(?:\b(?:manage\.py|django-admin)|\s-m\s+django)\s+{_OPTS}(flush|reset_db)\b",
       "Django flush (deletes every row)"),
    _r("iac.terraform-destroy", rf"\bterraform\s+{_OPTS}(destroy|apply\b{_REST}\s--?destroy\b(?!=false))", "terraform destroy"),
    _r("iac.tofu-destroy", rf"\btofu\s+{_OPTS}(destroy|apply\b{_REST}\s--?destroy\b(?!=false))", "OpenTofu destroy"),
    _r("iac.terragrunt-destroy",
       rf"\bterragrunt\s+{_OPTS}(?:(?:run-all|run)\s+{_OPTS}(?:--\s+)?)?(destroy|apply\b{_REST}\s--?destroy\b(?!=false))",
       "terragrunt destroy"),
    _r("iac.pulumi-destroy", r"\bpulumi\s+destroy\b", "pulumi destroy"),
    _r("k8s.delete", rf"\bkubectl\s+{_K8S_OPTS}delete\s+{_K8S_OPTS}{_K8S_STATEFUL}",
       "kubectl delete of stateful resources"),
    _r("k8s.helm-uninstall", r"\bhelm\s+(uninstall|delete)\b", "helm uninstall"),
    _r("cloud.aws-delete",
       rf"\baws\s+{_OPTS}(s3\s+rb\b|s3\s+rm\b{_REST}--recursive|rds\s+delete-|dynamodb\s+delete-table|ec2\s+delete-(volume|snapshot)|backup\s+delete-|s3api\s+delete-bucket\b|cloudformation\s+delete-stack\b)",
       "AWS delete of storage or backups"),
    _r("cloud.aws-s3-sync-delete", rf"\baws\s+{_OPTS}s3\s+sync\b{_REST}\s--delete\b",
       "aws s3 sync --delete (deletes objects missing from the source)"),
    # gcloud takes global options and release tracks (`alpha`, `beta`) before the group
    _r("cloud.gcloud-delete",
       rf"\bgcloud\s+{_OPTS}(?:(?:alpha|beta)\s+{_OPTS})?(sql\s+(instances|databases|backups)|compute\s+(disks|snapshots)"
       rf"|storage\s+buckets|firestore\s+databases|spanner\s+(instances|databases)|filestore\s+(instances|backups))\s+{_OPTS}delete\b"
       rf"|\bgcloud\s+{_OPTS}(?:(?:alpha|beta)\s+{_OPTS})?(storage\s+{_OPTS}rm|projects\s+{_OPTS}delete)\b",
       "Google Cloud delete of storage or backups"),
    _r("cloud.gsutil-delete",
       rf"\bgsutil\s+{_OPTS}(rb\b|rm\b{_REST}\s-([a-z]*[ra][a-z]*|-recursive|-all-versions)\b|rm\b{_REST}\*)",
       "gsutil bucket remove, recursive or wildcard delete"),
    _r("cloud.rclone-delete", rf"\brclone\s+{_OPTS}(purge|delete)\b", "rclone purge / delete"),
    _r("cloud.az-delete", rf"\baz\s+(sql|storage|disk|snapshot|backup|cosmosdb|group)\b{_ANY}\bdelete\b", "Azure delete of storage or backups"),
    _r("paas.railway", r"\brailway\s+(down|volume\s+delete|delete)\b", "Railway delete"),
    _r("paas.vercel", r"\bvercel\s+(remove|rm)\b", "Vercel remove"),
    _r("paas.fly", r"\bfly(ctl)?\s+(volumes?\s+(destroy|delete)|apps?\s+destroy|postgres\s+destroy)\b", "Fly destroy"),
    _r("paas.neon", r"\bneon(ctl)?\s+(branches?|projects?|databases?)\s+delete\b", "Neon delete"),
    _r("paas.firebase", rf"\bfirebase\s+{_OPTS}(firestore:delete|database:remove)\b", "Firebase data delete"),
    _r("paas.heroku", rf"\bheroku\s+{_OPTS}(apps:destroy|destroy|pg:backups:delete|addons:destroy)\b", "Heroku destroy"),
    _r("docker.volume",
       rf"\bdocker\s+{_OPTS}(volume\s+(rm|prune)|system\s+prune\b{_ANY}--volumes)|\bdocker([ -])compose\b{_ANY}\sdown\b{_ANY}\s(-v\b|--volumes\b)",
       "Docker volume delete"),
    # podman and nerdctl take docker's volume commands; `system reset` wipes all storage
    _r("container.volume",
       rf"\b(podman|nerdctl)\s+{_OPTS}(volume\s+(rm|prune)|system\s+prune\b{_ANY}--volumes|system\s+reset\b)"
       rf"|\b(podman|nerdctl)([ -])compose\b{_ANY}\sdown\b{_ANY}\s(-v\b|--volumes\b)",
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
QUERY_RULES: tuple[Rule, ...] = (
    _r("sql.drop", r"\bdrop\s+(database|schema|table)\b", "SQL DROP"),
    _r("sql.truncate", r"\btruncate\s+(table\s+)?[\w.$\[\]]+", "SQL TRUNCATE"),
    # The statement ends at `;`, a newline, `)`, a shell separator or redirect
    # or a `--` comment. An alias or a LIMIT may follow the table; a WHERE may not.
    _r("sql.delete-all",
       r"\bdelete\s+from\s+[\w.$\[\]]+(?:\s+(?:as\s+)?(?!where\b|limit\b)\w+)?(?!\s*where\b)(?:\s+limit\s+\d+)?"
       r"\s*(?:$|[;)|&\n<>]|--\s)",
       "SQL DELETE without WHERE"),
    _r("sql.alter-drop",
       r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?[\w.$\[\]]+\s+(?:[^;\n]{0,1024}?,\s*)?drop\s+"
       r"(?:column\b|constraint\b|(?!index\b|key\b|primary\b|foreign\b|default\b|check\b|trigger\b|if\b)\w+)",
       "SQL ALTER TABLE ... DROP COLUMN / CONSTRAINT"),
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

# Long input is matched in pieces of at most CHUNK_CHARS: whole lines, with
# the last WINDOW_OVERLAP characters' worth of lines repeated at the start of
# the next piece, and a single longer line cut into overlapping windows. The
# overlap is longer than any rule's reach, so a match is never cut in two.
# Above the hard caps the input is not matched at all and is denied.
CHUNK_CHARS = 16384
WINDOW_OVERLAP = 4096
MAX_COMMAND_CHARS = 65536
MAX_CONTENT_CHARS = 2_000_000

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
       r"(?:(?:sudo|exec|command|builtin|nohup|time|env|xargs|nice|watch|timeout[ \t]+[\d.]+\w?)[ \t]+){0,8}"
       r"(?:[a-z_]\w*=\S*[ \t]+){0,16}")  # on one line: `x=1\nx=1\n...` must not chain
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
    _r("unresolvable.remote-script", rf"\b{_DL}\b[^;&\n]{{0,1024}}{_STDIN_SINK}",
       "download piped into an interpreter (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"(?:\b(?:{_INTERP}|source)|(?:^|[\s;&|(])\.)\s+(?:-\S+\s+)*<?\s*<\(\s*(?:sudo\s+)?{_DL}\b",
       "download substituted into an interpreter (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"\b(?:eval|iex|invoke-expression)\b[^;|\n]{{0,512}}\b{_DL}\b|\s(?:-\w*c|-e|-r|-command|/c)\s+\$\(\s*{_DL}\b"
       rf"|{_CP}\$\(\s*{_DL}\b|\[scriptblock\]::create\([^\n]*\b{_DL}\b",
       "download evaluated as a command (the guard cannot see what it would run)"),
    _r("unresolvable.remote-script",
       rf"\b{_DL}\b(?=[^\n;&|]{{0,256}}+(?:&&|;|\n))[^\n;&|]{{0,256}}?[/\s=]([\w-][\w.-]*)(?=[\s;&])[^\n;&|]{{0,256}}+"
       rf"(?:&&|;|\n)(?:[\s\S]{{0,2048}}?(?:&&|;|\n))??\s*"
       rf"(?:sudo\s+)?(?:(?:{_INTERP}|source)\s+(?:-\S+\s+)*|&\s*)?(?:[\w.~/\\-]*[/\\])?\1{_WORD_END}",
       "download saved and then run (the guard cannot see what it would run)"),
)

INDIRECT_RULES: tuple[Rule, ...] = (
    _r("unresolvable.indirect", rf"{_CP}\$\((?![^()\n]*\)[/\\][^\s$`;&|()]*[^\s$`;&|()/\\](?:\s|$|[;&|)]))",
       "command produced by a command substitution (the guard cannot tell what would run)"),
    _r("unresolvable.indirect", rf"{_CP}eval\s+(?!{_EVAL_OK})[^;&|\n]*\$",
       "eval of a variable or substitution (the guard cannot tell what would run)"),
    _r("unresolvable.indirect",
       rf"\b(?:{_INTERP}|psql|mysql|su|wsl)\s+(?:[^\s;&|]+\s+){{0,64}}?(?:-\w*c|-e|-r|-command|--command|/c|/k)\s+"
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
# A rule can only match text that contains one of its words (lower case, after
# normalising), so a rule whose words are all absent is skipped. This keeps
# long ordinary content (a 2 MB file write) fast. Rules not listed always run.
_NEEDLES: dict[str, tuple[str, ...]] = {
    "fs.rm-recursive": ("rm",), "fs.win-delete": ("del", "erase", "rd", "rmdir", "format"), "fs.ps-delete": ("-r", "-f"),
    "fs.find-delete": ("find",), "fs.truncate-or-overwrite": ("truncate", "dd", "shred", "/dev/null", ":"),
    "fs.redirect-truncate": ("/dev/null", "clear-content", ">"), "fs.interpreter-delete": ("rm", "rimraf", "os."),
    "fs.python-rmtree": ("shutil",), "fs.robocopy-mirror": ("robocopy",),
    "fs.ps-format": ("format-volume", "clear-disk", "remove-partition"), "git.destructive": ("git",),
    "git.force-push-main": ("git",), "git.push-main-rewrite": ("git",), "git.repo-delete": ("gh",), "fs.mkfs": ("mkfs",),
    "fs.rsync-delete": ("rsync",), "db.dropdb": ("dropdb",), "db.mysqladmin-drop": ("mysqladmin",),
    "db.migrate-reset": ("prisma", "rails", "supabase", "heroku"), "db.prisma-force-reset": ("prisma",),
    "db.django-flush": ("manage.py", "django"), "iac.terraform-destroy": ("terraform",), "iac.tofu-destroy": ("tofu",),
    "iac.terragrunt-destroy": ("terragrunt",), "iac.pulumi-destroy": ("pulumi",), "k8s.delete": ("kubectl",),
    "k8s.helm-uninstall": ("helm",), "cloud.aws-delete": ("aws",), "cloud.aws-s3-sync-delete": ("aws",),
    "cloud.gcloud-delete": ("gcloud",), "cloud.gsutil-delete": ("gsutil",), "cloud.rclone-delete": ("rclone",),
    "cloud.az-delete": ("az",), "paas.railway": ("railway",), "paas.vercel": ("vercel",), "paas.fly": ("fly",),
    "paas.neon": ("neon",), "paas.firebase": ("firebase",), "paas.heroku": ("heroku",), "docker.volume": ("docker",),
    "container.volume": ("podman", "nerdctl"), "sql.drop": ("drop",), "sql.truncate": ("truncate",),
    "sql.delete-all": ("delete",), "sql.alter-drop": ("alter",), "db.redis-flush": ("flush",), "db.mongo-drop": (".drop",),
    "db.mongo-delete-all": ("deletemany", "remove"), "guard.self-authorize": ("perathos",),
    "guard.key-access": (".perathos", "signing.key"),
    "guard.self-disable": (".perathos", ".claude", ".cursor", "managed-settings", "claudecode"),
}


def _may_match(rule: Rule, low: str) -> bool:
    needles = _NEEDLES.get(rule.rule_id)
    return needles is None or any(n in low for n in needles)


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
    r"(?:^|[\s;&|(])(?:\.?/|bash\s+|sh\s+|zsh\s+|source\s+|\.\s+|python3?\s+|node\s+|pwsh\s+(?:-\S+\s+){0,16}"
    r"|powershell\s+(?:-\S+\s+){0,16}|psql\b[^;&|\n]{0,1024}?\s-f\s+|mysql\b[^;&|\n]{0,1024}?<\s*|sqlite3\b[^;&|\n]{0,1024}?<\s*)"
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


_PATH_WORD_SPLIT = re.compile(r"([\s=:]+)")


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
    parts = _PATH_WORD_SPLIT.split(text.replace("\\", "/"))
    return "".join(p if i % 2 else _fold_path(p) for i, p in enumerate(parts))


@dataclass(frozen=True)
class Match:
    rule_id: str
    description: str
    subject: str  # the text that was matched against (command or tool name)
    self_auth: bool = False


_HEREDOC_TO_SHELL = re.compile(rf"(?:^|[\s;&|(])(?:{_SH}|pwsh|powershell)\b[^|;&]*$", re.I)
# Programs whose quoted argument is itself a shell command line.
_SHELL_STRING_RUNNER = re.compile(
    rf"(?:^|[\s(])(?:{_SH}|su|sudo|ssh|eval|iex|invoke-expression|pwsh|powershell|cmd|wsl|watch|xargs|env|exec"
    r"|(?:docker|podman|kubectl)\s+exec)(?:\.exe)?(?:\s|$)", re.I)
_QUOTED_SEPARATORS = str.maketrans(dict.fromkeys(";|&<>\r\n", " "))
_BACKTICKS = re.compile(r"`([^`\n]*)`")


_HEREDOC_START = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1[^\n]*\n")


def _heredocs(command: str) -> list[tuple[int, int, bool]]:
    """(body start, body end, body is a shell script) for each heredoc.

    One pass over the lines and a lookup per `<<WORD`, so it stays linear on a
    long command (a regex with a lazy body search is quadratic when the
    terminator is missing). The terminator is a line holding only the word,
    optionally followed by `)`."""
    lines: dict[str, list[int]] = {}
    pos = 0
    for line in command.split("\n"):
        lines.setdefault(line.strip(" \t\r").rstrip(")").rstrip(" \t"), []).append(pos)
        pos += len(line) + 1
    out: list[tuple[int, int, bool]] = []
    end = 0
    for m in _HEREDOC_START.finditer(command):
        if m.start() < end:
            continue  # inside an earlier body
        starts = lines.get(m.group(2), [])
        k = bisect_left(starts, m.end())
        if k == len(starts):
            continue  # unterminated: not a heredoc body we can delimit
        body_end = max(m.end(), starts[k] - 1)
        line_start = command.rfind("\n", 0, m.start()) + 1
        out.append((m.end(), body_end, _HEREDOC_TO_SHELL.search(command[line_start:m.start()]) is not None))
        end = starts[k]
    return out


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
    # The segment is checked for a runner incrementally (new text plus a short
    # overlap), so a long command with many quotes stays linear.
    checked, tail, runner = 0, "", False
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
                if not runner:
                    window = tail + "".join(segment[checked:])
                    runner = _SHELL_STRING_RUNNER.search(window) is not None
                    checked, tail = len(segment), "x" + window[-64:]
                if not runner:
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
            checked, tail, runner = 0, "", False
        else:
            segment.append(ch)
        out.append(ch)
        i += 1
    view = _BACKTICKS.sub(r"$(\1)", "".join(out))
    return re.sub(r"[ \t]+", " ", re.sub(r"['\"]", "", view))


def _command_kind(simple: str) -> str:
    """'client' (runs a database client), 'text' (only carries text) or 'other'."""
    m = _PROGRAM.match(simple)
    prog = re.split(r"[/\\]", m.group(1))[-1].lower().removesuffix(".exe") if m else ""
    if prog in _TEXT_ONLY_PROGRAMS and not _TEXT_PROGRAM_RUNS.search(simple):
        return "text"
    return "client" if _DB_CLIENT.search(simple) else "other"


def _query_texts(text: str, norm: str, view: str | None) -> tuple[list[str], list[str]]:
    """(texts for the query rules, texts that may also use the client-only
    rules). ``view`` is the structure view of a shell command line, or None
    for scripts, file content and MCP arguments (all the text counts)."""
    if view is None:
        return [norm], ([norm] if _DB_CLIENT.search(norm) else [])
    base: list[str] = []
    client: list[str] = []
    # Parentheses are not split on: quoted code (`db.users.drop()`) keeps them.
    for pipeline in re.split(r"\|\||&&|[;&\n]", view.replace("|&", "|")):
        simples = pipeline.split("|")
        kinds = [_command_kind(s) for s in simples]
        if "client" in kinds[1:]:
            client.append(normalize_command(pipeline))  # text piped into a client is a query
            continue
        for simple, kind in zip(simples, kinds):
            if kind == "client":
                if _CLIENT_READS_INPUT.search(simple):
                    return [norm], [norm]  # `psql -f f.sql`: anything on the line may be the query
                client.append(normalize_command(simple))
            elif kind == "other":
                base.append(normalize_command(simple))
    return base + client, client


def _query_match(text: str, norm: str, view: str | None) -> Match | None:
    """The query-language rules, applied only where a query can be (see QUERY_RULES)."""
    texts, client_texts = _query_texts(text, norm, view)
    for rules, ts in ((QUERY_RULES, texts), (CLIENT_QUERY_RULES, client_texts)):
        for rule in rules:
            for t in ts:
                if _may_match(rule, t.lower()) and rule.pattern.search(t):
                    return Match(rule.rule_id, rule.description, text)
    return None


def _too_long(text: str, limit: int, *, command: bool) -> Match:
    if command:
        desc = (f"command too long to check safely ({len(text)} chars > {limit}); split it or write the "
                f"content with the Write tool")
    else:
        desc = f"content too long to check safely ({len(text)} chars > {limit}); split it into smaller pieces"
    return Match("guard.too-long", desc, text)


def _first_match(text: str, *, include_self_auth: bool = True, shell: str | None = None,
                 queries: bool = True) -> Match | None:
    """``shell`` is the shell tool's name when ``text`` is a command line typed
    into a shell; only then are the variable-indirection rules applied.
    ``queries=False`` skips the query-language rules (a data heredoc body)."""
    norm = normalize_command(text)
    low = norm.lower()
    if include_self_auth:
        paths = _normalize_paths(norm)
        low_paths = paths.lower()
        for rule in SELF_AUTH_RULES:
            if _may_match(rule, low_paths) and rule.pattern.search(paths):
                if rule.rule_id == "guard.self-disable" and _READ_ONLY_PREFIX.match(paths):
                    continue
                return Match(rule.rule_id, rule.description, text, self_auth=True)
    for rule in SHELL_RULES:
        if _may_match(rule, low) and rule.pattern.search(norm):
            return Match(rule.rule_id, rule.description, text)
    # The structure view is needed for redirects, shell command lines and downloads.
    need_view = shell is not None or ">" in text or _PREFILTER_REMOTE.search(text) is not None
    view = _structure_view(text) if need_view else ""
    for rule in REDIRECT_RULES:
        if need_view and rule.pattern.search(view):
            return Match(rule.rule_id, rule.description, text)
    hit = _query_match(text, norm, view if shell is not None else None) if queries else None
    if hit is not None:
        return hit
    if shell is None and not _PREFILTER_REMOTE.search(text):
        return None
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
        hit = _scan_content(content)
        if hit is not None:
            return Match(f"script:{hit.rule_id}", f"{hit.description} inside {name}", command, self_auth=hit.self_auth)
    return None


def _pieces(text: str):
    """``text`` in pieces of at most CHUNK_CHARS (see CHUNK_CHARS)."""
    step = CHUNK_CHARS - WINDOW_OVERLAP
    chunk: list[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        if len(line) > CHUNK_CHARS:
            if chunk:
                yield "".join(chunk)
                chunk, size = [], 0
            for start in range(0, len(line) - WINDOW_OVERLAP, step):
                # a window that starts mid-line must not look like a command start
                yield line[start:start + CHUNK_CHARS] if start == 0 else "x " + line[start:start + CHUNK_CHARS]
            continue
        if chunk and size + len(line) > CHUNK_CHARS:
            yield "".join(chunk)
            keep: list[str] = []  # repeat the last lines, up to the overlap
            kept = 0
            for prev in reversed(chunk):
                if kept + len(prev) > WINDOW_OVERLAP:
                    break
                keep.insert(0, prev)
                kept += len(prev)
            chunk, size = keep, kept
        chunk.append(line)
        size += len(line)
    if chunk:
        yield "".join(chunk)


def _scan_content(text: str, *, include_self_auth: bool = True, shell: str | None = None,
                  queries: bool = True) -> Match | None:
    """``_first_match`` for file content, script files, MCP arguments and
    heredoc bodies, which may be long: matched in pieces (see CHUNK_CHARS);
    denied unmatched only above MAX_CONTENT_CHARS."""
    if len(text) > MAX_CONTENT_CHARS:
        return _too_long(text, MAX_CONTENT_CHARS, command=False)
    if len(text) <= CHUNK_CHARS:
        return _first_match(text, include_self_auth=include_self_auth, shell=shell, queries=queries)
    for piece in _pieces(text):
        hit = _first_match(piece, include_self_auth=include_self_auth, shell=shell, queries=queries)
        if hit is not None:
            return replace(hit, subject=text)
    return None


def _scan_command(command: str, shell: str) -> Match | None:
    """A shell command line. Longer than CHUNK_CHARS, its heredoc bodies are
    matched as content and the rest in pieces; longer than MAX_COMMAND_CHARS it
    is denied unmatched (fail closed)."""
    if len(command) > MAX_COMMAND_CHARS:
        return _too_long(command, MAX_COMMAND_CHARS, command=True)
    if len(command) <= CHUNK_CHARS:
        return _first_match(command, shell=shell)
    parts, last = [], 0
    for start, end, to_shell in _heredocs(command):
        # a data body (`cat > f.sql <<EOF`) is judged as on a short command
        # line: the shell rules apply, the query rules do not
        hit = _scan_content(command[start:end], shell=shell if to_shell else None, queries=to_shell)
        if hit is not None:
            return replace(hit, subject=command)
        parts.append(command[last:start])
        last = end
    parts.append(command[last:])
    hit = _scan_content("".join(parts), shell=shell)
    return replace(hit, subject=command) if hit is not None else None


def evaluate(tool_name: str, tool_input: Any, cwd: str | os.PathLike | None = None) -> Match | None:
    """Return the first destructive-action rule a tool call matches, or None.

    ``cwd`` lets the guard read a script the command would run and scan it.
    """
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name in _SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        hit = _scan_command(command, tool_name)
        if hit is not None or len(command) > MAX_COMMAND_CHARS:
            return hit
        return _scan_script_files(command, cwd)
    if tool_name in _FILE_TOOLS_WITH_PATH:
        target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        norm_target = _normalize_paths(normalize_command(target))
        for rule in SELF_AUTH_RULES[1:]:
            if rule.pattern.search(norm_target) and (tool_name in _WRITE_TOOLS or rule.rule_id == "guard.key-access"):
                return Match(rule.rule_id, rule.description, target, self_auth=True)
        if tool_name in _WRITE_TOOLS and target.lower().endswith(_SCRIPT_EXT):
            parts = [str(tool_input.get(k) or "") for k in ("content", "new_string", "new_source")]
            parts += [str(e.get("new_string") or "") for e in tool_input.get("edits") or [] if isinstance(e, dict)]
            body = "\n".join(p for p in parts if p)
            hit = _scan_content(body, include_self_auth=False)
            if hit is not None and hit.rule_id == "guard.too-long":
                return replace(hit, subject=target)
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
            hit = _scan_content(text)
            if hit is not None:
                desc = hit.description if hit.self_auth or hit.rule_id == "guard.too-long" else \
                    f"{hit.description} inside an MCP tool call"
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
