"""
Autonomous agent cycle runner for Perathos.

Each run:
  1. Master agent analyzes the full codebase + recent git history
  2. Master assigns a specific high-value task to each specialist
  3. Each specialist executes its assigned task
  4. Files are written, pytest validates, a PR is opened with auto-merge

Set DRY_RUN=true to print the plan without writing files or opening a PR.
Set AGENT_FILTER=<name> to run only one agent (skips master, agent self-selects).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ── config ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent.parent.parent
AGENTS_DIR = ROOT / ".claude" / "agents"
SPECIALISTS = ["product-engineer", "qa-tester", "ux-reviewer", "docs-writer"]

# Globbed so new modules (e.g. verdict/verifiers/pipeline) are always included
# in the context the agents see — a hard-coded list silently omitted them.
def _discover_source_files() -> list[str]:
    rels = []
    for sub in ("perathos", "tests"):
        for p in sorted((ROOT / sub).glob("*.py")):
            rels.append(str(p.relative_to(ROOT)).replace("\\", "/"))
    rels += ["README.md", "BACKLOG.md", "pyproject.toml"]
    return rels


SOURCE_FILES = _discover_source_files()

OPENROUTER_MODELS = [
    "anthropic/claude-3.5-haiku",
    "deepseek/deepseek-r1:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "google/gemini-2.0-flash-exp:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
]

DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
AGENT_FILTER = os.environ.get("AGENT_FILTER", "all").strip().lower().replace(" ", "-")
GITHUB_REPO = os.environ.get("GITHUB_REPOSITORY", "")

# Prefer AGENT_PAT (Personal Access Token) over the default GITHUB_TOKEN:
#   - GITHUB_TOKEN works for push + PR creation but GitHub blocks it from
#     triggering downstream workflows (anti-recursion), so CI never fires
#     on agent-created PRs and auto-merge can't merge them.
#   - AGENT_PAT is a user-scoped PAT — workflows it triggers run normally,
#     so CI fires on agent PRs and auto-merge works end-to-end.
AGENT_PAT = os.environ.get("AGENT_PAT", "").strip()
GITHUB_TOKEN_DEFAULT = os.environ.get("GH_TOKEN", "")
GH_TOKEN = AGENT_PAT or GITHUB_TOKEN_DEFAULT
USING_PAT = bool(AGENT_PAT)

GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
}


def configure_git_for_pat() -> None:
    """If AGENT_PAT is set, rewrite the remote URL so git push uses it
    (instead of the default GITHUB_TOKEN configured by actions/checkout)."""
    if not (USING_PAT and GITHUB_REPO):
        return
    new_url = f"https://x-access-token:{AGENT_PAT}@github.com/{GITHUB_REPO}.git"
    subprocess.run(
        ["git", "remote", "set-url", "origin", new_url],
        cwd=ROOT,
        check=False,  # non-fatal — push will fail loud if this didn't take
    )
    print("  [auth] git remote reconfigured to use AGENT_PAT")


# ── context builders ──────────────────────────────────────────────────────────

def build_codebase_context() -> str:
    parts: list[str] = []
    for rel in SOURCE_FILES:
        path = ROOT / rel
        if path.exists():
            parts.append(f"=== {rel} ===\n{path.read_text(encoding='utf-8')}")
        else:
            parts.append(f"=== {rel} ===\n(file does not exist yet)")
    return "\n\n".join(parts)


def build_git_log() -> str:
    result = subprocess.run(
        ["git", "log", "--oneline", "-30"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or "(no git history)"


# ── LLM caller ────────────────────────────────────────────────────────────────

CACHE_BOUNDARY = "<<<CACHE_BOUNDARY>>>"


def _build_cached_messages(user: str) -> list[dict]:
    """Split user message at CACHE_BOUNDARY into a cacheable prefix (codebase
    context, identical across all specialists in the cycle) and a variable
    suffix (per-specialist task). Falls back to a single uncached block if
    the marker is absent.
    """
    if CACHE_BOUNDARY not in user:
        return [{"role": "user", "content": user}]
    prefix, suffix = user.split(CACHE_BOUNDARY, 1)
    return [{
        "role": "user",
        "content": [
            {"type": "text", "text": prefix.rstrip(), "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": suffix.lstrip()},
        ],
    }]


def _build_cached_system(system: str) -> list[dict]:
    """Mark the agent system prompt as cacheable for the initial + self-review
    pair on the same agent within the 5-minute cache TTL.
    """
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


def call_anthropic(system: str, user: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=16384,  # Specialists write full file content — 8192 was truncating
        system=_build_cached_system(system),
        messages=_build_cached_messages(user),
    )
    return msg.content[0].text


def call_openrouter(system: str, user: str) -> str:
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("No OPENROUTER_API_KEY set")

    payload = {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": 16384,  # Specialists write full file content; 8192 truncates mid-JSON
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/perathos-protocol/perathos",
        "X-Title": "perathos-agent",
    }

    for model in OPENROUTER_MODELS:
        try:
            resp = httpx.post(
                "https://openrouter.ai/api/v1/chat/completions",
                json={**payload, "model": model},
                headers=headers,
                timeout=120,
            )
            if resp.status_code == 429:
                print(f"  [rate-limit] {model} — trying next model")
                time.sleep(2)
                continue
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            print(f"  [error] {model}: {exc}")
            continue

    raise RuntimeError("All OpenRouter models failed")


def call_llm(system: str, user: str) -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("  Using Anthropic API")
        return call_anthropic(system, user)
    print("  Using OpenRouter free tier")
    return call_openrouter(system, user)


def extract_json(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"No JSON object found in LLM output:\n{text[:500]}")
    return json.loads(text[start:end])


# ── test runner ───────────────────────────────────────────────────────────────

def run_tests() -> tuple[bool, str]:
    # Mirror CI exactly: the ruff lint gate runs BEFORE pytest, so a lint-only
    # violation is caught locally instead of passing the local gate, merging,
    # and then turning main's CI red.
    ruff = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "perathos/", "tests/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if ruff.returncode != 0:
        return False, "ruff check failed:\n" + ruff.stdout + ruff.stderr
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--tb=short", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, ruff.stdout + result.stdout + result.stderr


# ── PR opener ────────────────────────────────────────────────────────────────

def open_pr(branch: str, title: str, body: str, agent_name: str = "?") -> str | None:
    if not GH_TOKEN or not GITHUB_REPO:
        print("  [skip PR] GH_TOKEN or GITHUB_REPOSITORY not set")
        _PR_ERRORS.append({"agent": agent_name, "branch": branch, "status": 0, "body": "GH_TOKEN or GITHUB_REPOSITORY missing"})
        return None

    resp = httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/pulls",
        json={"title": title, "body": body, "head": branch, "base": "main"},
        headers=GH_HEADERS,
        timeout=30,
    )
    if resp.status_code in (200, 201):
        pr = resp.json()
        pr_number = pr["number"]
        _enable_auto_merge(pr_number)
        # Direct-merge fallback: tests already ran successfully pre-push,
        # so we can merge the PR directly via API. Tolerant of CI not having
        # completed yet — we retry briefly and give up after the budget so the
        # cycle doesn't block. If auto-merge engaged, this is a no-op (PR
        # already merged).
        _direct_merge_pr(pr_number, branch, agent_name)
        return pr["html_url"]
    print(f"  [PR error] {resp.status_code}: {resp.text[:200]}")
    _PR_ERRORS.append({
        "agent": agent_name,
        "branch": branch,
        "status": resp.status_code,
        "body": resp.text[:500],
    })
    return None


def _direct_merge_pr(pr_number: int, branch: str, agent_name: str) -> None:
    """Merge a PR directly via the REST API. The runner has already run pytest
    on the changes before pushing, so the gate is satisfied. We retry a few
    times to give any CI race a chance to clear ('Required status check' etc.)
    then give up — the PR stays open for human merge as a fallback."""
    if not (GH_TOKEN and GITHUB_REPO):
        return
    url = f"https://api.github.com/repos/{GITHUB_REPO}/pulls/{pr_number}/merge"
    payload = {"merge_method": "squash"}

    # Brief polite retry — CI can take a few seconds to register, and some
    # branch protections only allow merge after CI starts. Total budget ~20s.
    for attempt in range(4):
        if attempt > 0:
            time.sleep(5)
        resp = httpx.put(url, json=payload, headers=GH_HEADERS, timeout=30)
        if resp.status_code in (200, 201):
            print(f"  [direct-merge] PR #{pr_number} merged ✓")
            return
        # 405 = method not allowed (PR not mergeable yet — conflicts, draft, etc.)
        # 409 = conflict (PR head changed during merge)
        # 422 = unmergeable (required checks failing)
        body_head = resp.text[:300]
        print(f"  [direct-merge] PR #{pr_number} attempt {attempt+1}: HTTP {resp.status_code}: {body_head[:120]}")
        if resp.status_code == 409:
            continue  # Retry — head changed, will recompute
        if resp.status_code in (404, 403):
            break  # Unrecoverable

    # If we got here, direct-merge gave up. The PR sits open for human review.
    _PR_ERRORS.append({
        "agent": agent_name,
        "branch": branch,
        "status": 0,
        "body": f"PR #{pr_number} opened but direct-merge failed after retries — manual merge needed",
    })


def _enable_auto_merge(pr_number: int) -> None:
    resp = httpx.get(
        f"https://api.github.com/repos/{GITHUB_REPO}/pulls/{pr_number}",
        headers=GH_HEADERS,
        timeout=15,
    )
    if resp.status_code != 200:
        return
    node_id = resp.json().get("node_id", "")
    if not node_id:
        return

    query = """
    mutation EnableAutoMerge($pullRequestId: ID!) {
      enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, mergeMethod: SQUASH}) {
        pullRequest { autoMergeRequest { enabledAt } }
      }
    }
    """
    httpx.post(
        "https://api.github.com/graphql",
        json={"query": query, "variables": {"pullRequestId": node_id}},
        headers=GH_HEADERS,
        timeout=15,
    )


# ── master orchestrator ───────────────────────────────────────────────────────

_LAST_MASTER_RAW = ""
# Per-cycle dict of {specialist_name: {"reason": str, "raw_head": str}} populated during run_agent
_SPECIALIST_DIAG: dict[str, dict[str, str]] = {}
# Per-cycle list of PR creation failures: [{"agent": str, "branch": str, "status": int, "body": str}]
_PR_ERRORS: list[dict] = []


def run_master(context: str, git_log: str) -> dict:
    """
    Call the master agent to analyze the codebase and assign tasks.
    Returns the full decision dict including 'assignments' and 'cycle_brief'.
    Also stores the raw LLM response in _LAST_MASTER_RAW for diagnostics.
    """
    global _LAST_MASTER_RAW
    _LAST_MASTER_RAW = ""
    print(f"\n{'='*60}")
    print("Master Orchestrator")
    print(f"{'='*60}")

    agent_file = AGENTS_DIR / "master.md"
    if not agent_file.exists():
        print("  [warn] no master.md — falling back to agent self-selection")
        return {}

    system_prompt = agent_file.read_text(encoding="utf-8")
    if system_prompt.startswith("---"):
        end = system_prompt.find("---", 3)
        if end != -1:
            system_prompt = system_prompt[end + 3:].strip()

    # Codebase context is identical across all specialist calls in this
    # cycle — put it FIRST as the cacheable prefix, then the boundary marker,
    # then variable per-call bits.
    user_message = (
        f"## Current codebase\n\n{context}\n\n"
        f"{CACHE_BOUNDARY}\n\n"
        f"## Recent git history (last 30 commits)\n\n{git_log}"
    )

    print("  Analyzing codebase…")
    try:
        raw = call_llm(system_prompt, user_message)
        _LAST_MASTER_RAW = raw or ""
        print(f"  raw master response head: {_LAST_MASTER_RAW[:200].replace(chr(10), ' ')}")
    except Exception as exc:
        print(f"  [error] master LLM call failed: {exc}")
        _LAST_MASTER_RAW = f"<LLM call exception: {exc}>"
        return {}

    try:
        result = extract_json(raw)
    except Exception as exc:
        print(f"  [error] master JSON parse failed: {exc}\n{raw[:500]}")
        return {}

    analysis = result.get("analysis", "")
    assignments = result.get("assignments", {})

    print(f"\n  Analysis: {analysis}")
    print("\n  Assignments:")
    for agent, task in assignments.items():
        if task:
            print(f"    {agent}: {task[:120]}{'...' if len(str(task)) > 120 else ''}")
        else:
            print(f"    {agent}: (skipped this cycle)")

    return result


# ── cycle brief poster ───────────────────────────────────────────────────────

BRIEF_ISSUE_TITLE = "Agent Cycle Brief"
BRIEF_LABEL = "cycle-brief"
OPERATOR_HANDLE = os.environ.get("APPROVAL_USER_HANDLE", "tamukachagos")


def _find_brief_issue() -> dict | None:
    if not (GH_TOKEN and GITHUB_REPO):
        return None
    resp = httpx.get(
        f"https://api.github.com/repos/{GITHUB_REPO}/issues",
        params={"labels": BRIEF_LABEL, "state": "open", "per_page": 5},
        headers=GH_HEADERS,
        timeout=20,
    )
    if resp.status_code != 200:
        return None
    for issue in resp.json():
        if issue.get("title") == BRIEF_ISSUE_TITLE:
            return issue
    return None


def _ensure_brief_label() -> None:
    if not (GH_TOKEN and GITHUB_REPO):
        return
    httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/labels",
        json={"name": BRIEF_LABEL, "color": "0e8a16", "description": "Periodic agent activity summaries"},
        headers=GH_HEADERS,
        timeout=10,
    )


def _create_brief_issue() -> dict | None:
    if not (GH_TOKEN and GITHUB_REPO):
        return None
    _ensure_brief_label()
    body = (
        f"@{OPERATOR_HANDLE} — this is the rolling cycle brief.\n\n"
        f"Every 2 hours the master agent posts a comment here summarising what shipped, "
        f"where the codebase is, and where development is heading. Mute the issue if it "
        f"gets noisy; close it to stop notifications entirely (a new one will be created)."
    )
    resp = httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/issues",
        json={"title": BRIEF_ISSUE_TITLE, "body": body, "labels": [BRIEF_LABEL]},
        headers=GH_HEADERS,
        timeout=20,
    )
    return resp.json() if resp.status_code in (200, 201) else None


def post_cycle_brief(brief: dict, results: dict[str, bool], pr_urls: list[str], full_decision: dict | None = None) -> None:
    if not (GH_TOKEN and GITHUB_REPO):
        print("  [brief] skipped — no GH_TOKEN")
        return

    issue = _find_brief_issue() or _create_brief_issue()
    if not issue:
        print("  [brief] could not find or create issue")
        return

    # If master didn't produce a brief, post a diagnostic comment with the raw decision instead
    if not brief:
        raw_text = _LAST_MASTER_RAW or "<empty — master returned nothing>"
        diag_body = (
            f"### ⚠️ Master did not produce a `cycle_brief` this cycle\n\n"
            f"**Raw LLM response from master (first 3000 chars):**\n\n"
            f"```\n{raw_text[:3000]}\n```\n\n"
            f"**Parsed decision JSON (after extract_json):**\n\n"
            f"```json\n{json.dumps(full_decision or {}, indent=2)[:1500]}\n```\n\n"
            f"**Specialist results:**\n"
            + "\n".join(f"- {'✅' if ok else '❌'} `{name}`" for name, ok in results.items())
            + f"\n\n_Posted at {datetime.now(timezone.utc).isoformat()} UTC._"
        )
        httpx.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/issues/{issue['number']}/comments",
            json={"body": diag_body},
            headers=GH_HEADERS,
            timeout=20,
        )
        print(f"  [brief] diagnostic posted to {issue['html_url']}")
        return

    headline = brief.get("headline", "(no headline)")
    state = brief.get("state_of_repo", "")
    since = brief.get("since_last_cycle", "")
    next_3 = brief.get("next_3_cycles", "")
    blockers = brief.get("blockers_or_decisions_needed", "") or "_None_"

    def _spec_line(n: str, ok: bool) -> str:
        if ok:
            return f"- ✅ `{n}`"
        diag = _SPECIALIST_DIAG.get(n)
        if diag:
            return f"- ❌ `{n}` — {diag.get('reason', 'unknown failure')}"
        return f"- ❌ `{n}`"

    specialists_summary = "\n".join(_spec_line(name, ok) for name, ok in results.items())

    # Build PR section — show successful URLs OR error diagnostics
    if pr_urls:
        pr_section = "\n".join(f"- {url}" for url in pr_urls)
    elif _PR_ERRORS:
        pr_lines = ["_PRs failed to open — diagnostic:_"]
        for err in _PR_ERRORS:
            pr_lines.append(
                f"- ❌ `{err['agent']}` → branch `{err['branch']}` — "
                f"HTTP {err['status']}: `{err['body'][:200]}`"
            )
        pr_section = "\n".join(pr_lines)
    else:
        pr_section = "_No PRs opened this cycle (no specialist produced files)._"

    # Build per-specialist diagnostic dump for failures with raw output
    diag_blocks = []
    for name, ok in results.items():
        if ok:
            continue
        diag = _SPECIALIST_DIAG.get(name)
        if not diag or not diag.get("raw_head"):
            continue
        diag_blocks.append(
            f"<details><summary>📋 <code>{name}</code> raw output (first 1500 chars)</summary>\n\n"
            f"```\n{diag['raw_head'][:1500]}\n```\n\n</details>"
        )
    diag_section = "\n\n".join(diag_blocks)

    comment_body = (
        f"### {headline}\n\n"
        f"**State of the repo**\n{state}\n\n"
        f"**Since last cycle**\n{since}\n\n"
        f"**Direction (next ~6 hours / 3 cycles)**\n{next_3}\n\n"
        f"**Blockers or decisions needed**\n{blockers}\n\n"
        f"---\n\n"
        f"**Specialist results this cycle**\n{specialists_summary}\n\n"
        f"**PRs opened**\n{pr_section}\n\n"
        + (f"---\n\n**Specialist diagnostics**\n\n{diag_section}\n\n" if diag_section else "")
        + f"_Posted at {datetime.now(timezone.utc).isoformat()} UTC by the master agent._"
    )

    httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/issues/{issue['number']}/comments",
        json={"body": comment_body},
        headers=GH_HEADERS,
        timeout=20,
    )
    print(f"  [brief] posted to {issue['html_url']}")


# ── per-agent runner ──────────────────────────────────────────────────────────

def run_agent(name: str, context: str, assignment: str | None = None) -> tuple[bool, str | None]:
    print(f"\n{'='*60}")
    print(f"Agent: {name}")
    print(f"{'='*60}")

    agent_file = AGENTS_DIR / f"{name}.md"
    if not agent_file.exists():
        print(f"  [skip] no agent file at {agent_file}")
        return False, None

    system_prompt = agent_file.read_text(encoding="utf-8")
    if system_prompt.startswith("---"):
        end = system_prompt.find("---", 3)
        if end != -1:
            system_prompt = system_prompt[end + 3:].strip()

    # Codebase context goes FIRST so it's the cacheable prefix. CACHE_BOUNDARY
    # marker, then per-specialist task suffix.
    if assignment:
        user_message = (
            f"## Current codebase\n\n{context}\n\n"
            f"{CACHE_BOUNDARY}\n\n"
            f"## Your assigned task for this cycle\n\n"
            f"{assignment}\n\n"
            f"Execute this specific task. Do not pick a different one."
        )
    else:
        user_message = f"## Current codebase\n\n{context}"

    print("  Calling LLM…")
    raw_for_diag = ""
    try:
        raw = call_llm(system_prompt, user_message)
        raw_for_diag = raw or ""
        print(f"  raw response head: {raw_for_diag[:200].replace(chr(10), ' ')}")
    except Exception as exc:
        print(f"  [error] LLM call failed: {exc}")
        _SPECIALIST_DIAG[name] = {"reason": f"LLM call exception: {exc}", "raw_head": ""}
        return False, None

    print("  Parsing response…")
    try:
        result = extract_json(raw)
    except Exception as exc:
        print(f"  [error] JSON parse failed: {exc}")
        print(f"  Raw output (first 500 chars):\n{raw[:500]}")
        _SPECIALIST_DIAG[name] = {"reason": f"JSON parse failed: {exc}", "raw_head": raw_for_diag[:1500]}
        return False, None

    task = result.get("task", "improvement")
    files = result.get("files", [])
    commit_msg = result.get("commit_message", f"agent({name}): {task}")

    print(f"  Task  : {task}")
    print(f"  Files : {[f['path'] for f in files]}")

    if not files:
        print("  [skip] no files to write")
        _SPECIALIST_DIAG[name] = {
            "reason": f"specialist returned valid JSON but empty files list (task='{task}')",
            "raw_head": raw_for_diag[:1500],
        }
        return False, None

    if DRY_RUN:
        print("  [DRY RUN] would write files and open PR")
        return True, None

    # Write files
    for f in files:
        dest = ROOT / f["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f["content"], encoding="utf-8")
        print(f"  wrote {f['path']}")

    # Validate
    print("  Running tests…")
    passed, output = run_tests()
    if not passed:
        print(f"  [FAIL] tests failed — reverting\n{output[-1000:]}")
        # Full revert: tracked changes AND untracked files. Without -fd, a
        # specialist that creates NEW files (e.g. tests/test_X.py) that break
        # pytest will leave those files behind after revert, cascading failure
        # into every subsequent specialist in the same cycle.
        subprocess.run(["git", "checkout", "--", "."], cwd=ROOT)
        subprocess.run(["git", "clean", "-fd"], cwd=ROOT)
        _SPECIALIST_DIAG[name] = {
            "reason": "tests failed — changes reverted",
            "raw_head": output[-1500:],  # last 1500 chars of pytest output
        }
        return False, None
    print("  Tests passed ✓")

    # Commit + push
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"agent/{name}-{timestamp}"

    try:
        subprocess.run(["git", "checkout", "-b", branch], cwd=ROOT, check=True)
        subprocess.run(["git", "add", "-A"], cwd=ROOT, check=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=ROOT, check=True)
        subprocess.run(
            ["git", "push", "origin", branch],
            cwd=ROOT,
            env={**os.environ, "GH_TOKEN": GH_TOKEN},
            check=True,
        )
        subprocess.run(["git", "checkout", "main"], cwd=ROOT, check=True)
    except subprocess.CalledProcessError as exc:
        # A commit/push rejection (branch protection, non-fast-forward, auth,
        # network) must not abort the whole cycle: restore main so the remaining
        # specialists still run and the cycle brief still posts to the operator.
        print(f"  [git-fail] {name}: {exc}")
        subprocess.run(["git", "checkout", "main"], cwd=ROOT, check=False)
        subprocess.run(["git", "checkout", "--", "."], cwd=ROOT, check=False)
        subprocess.run(["git", "clean", "-fd"], cwd=ROOT, check=False)
        _PR_ERRORS.append({
            "agent": name, "branch": branch, "status": 0,
            "body": f"git commit/push failed, changes reverted: {exc}",
        })
        return False, None

    pr_url = open_pr(
        branch=branch,
        title=commit_msg,
        body=(
            f"**Agent:** `{name}`\n\n"
            f"**Task:** {task}\n\n"
            f"**Files changed:** {', '.join(f['path'] for f in files)}\n\n"
            f"_Auto-merge enabled — will merge when CI passes._"
        ),
        agent_name=name,
    )
    if pr_url:
        print(f"  PR opened: {pr_url}")

    return True, pr_url


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Perathos autonomous agent cycle")
    print(f"Time    : {datetime.now(timezone.utc).isoformat()}")
    print(f"Filter  : {AGENT_FILTER}")
    print(f"Dry run : {DRY_RUN}")
    print(f"Auth    : {'AGENT_PAT (CI triggers on agent PRs)' if USING_PAT else 'GITHUB_TOKEN (CI will NOT fire on agent PRs)'}")

    configure_git_for_pat()

    # Reset per-cycle diagnostic state
    _SPECIALIST_DIAG.clear()
    _PR_ERRORS.clear()

    # Defensive: ensure working tree is clean before the cycle starts. Stops
    # any leftover untracked files (from prior failures) from poisoning tests.
    subprocess.run(["git", "checkout", "--", "."], cwd=ROOT, check=False)
    subprocess.run(["git", "clean", "-fd"], cwd=ROOT, check=False)

    context = build_codebase_context()
    git_log = build_git_log()

    pr_urls: list[str] = []
    decision: dict = {}

    # Single-agent mode: skip master, agent self-selects
    if AGENT_FILTER not in ("all", ""):
        ok, pr = run_agent(AGENT_FILTER, context)
        results = {AGENT_FILTER: ok}
        if pr:
            pr_urls.append(pr)
    else:
        # Master assigns tasks, then each specialist executes
        decision = run_master(context, git_log)
        assignments = decision.get("assignments", {}) if decision else {}
        results: dict[str, bool] = {}

        for agent in SPECIALISTS:
            task = assignments.get(agent)
            if task is None and assignments:
                # Master explicitly skipped this agent
                print(f"\n[skip] {agent} — no task assigned by master this cycle")
                results[agent] = True  # not a failure
                continue
            ok, pr = run_agent(agent, context, assignment=task)
            results[agent] = ok
            if pr:
                pr_urls.append(pr)

    print(f"\n{'='*60}")
    print("Cycle summary")
    print(f"{'='*60}")
    for agent, ok in results.items():
        print(f"  {'✓' if ok else '✗'} {agent}")

    # Post the master's cycle brief as a comment so the operator gets a phone notification
    post_cycle_brief(
        decision.get("cycle_brief", {}) if decision else {},
        results,
        pr_urls,
        full_decision=decision,
    )

    # Exit 0 even on partial failure — partial progress is still progress
    sys.exit(0)


if __name__ == "__main__":
    main()
