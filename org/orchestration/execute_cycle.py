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

SOURCE_FILES = [
    "perathos/__init__.py",
    "perathos/bundle.py",
    "perathos/canonical.py",
    "perathos/cli.py",
    "perathos/inspector.py",
    "perathos/signing.py",
    "perathos/storage.py",
    "tests/test_bundle.py",
    "tests/test_canonical.py",
    "tests/test_signing.py",
    "README.md",
    "BACKLOG.md",
    "pyproject.toml",
]

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
GH_TOKEN = os.environ.get("GH_TOKEN", "")

GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
}


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

def call_anthropic(system: str, user: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": user}],
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
        "max_tokens": 8192,
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
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


# ── PR opener ────────────────────────────────────────────────────────────────

def open_pr(branch: str, title: str, body: str) -> str | None:
    if not GH_TOKEN or not GITHUB_REPO:
        print("  [skip PR] GH_TOKEN or GITHUB_REPOSITORY not set")
        return None

    resp = httpx.post(
        f"https://api.github.com/repos/{GITHUB_REPO}/pulls",
        json={"title": title, "body": body, "head": branch, "base": "main"},
        headers=GH_HEADERS,
        timeout=30,
    )
    if resp.status_code in (200, 201):
        pr = resp.json()
        _enable_auto_merge(pr["number"])
        return pr["html_url"]
    print(f"  [PR error] {resp.status_code}: {resp.text[:200]}")
    return None


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

def run_master(context: str, git_log: str) -> dict[str, str | None]:
    """
    Call the master agent to analyze the codebase and assign tasks.
    Returns a dict mapping agent name → task string (or None to skip).
    """
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

    user_message = (
        f"## Recent git history (last 30 commits)\n\n{git_log}\n\n"
        f"## Current codebase\n\n{context}"
    )

    print("  Analyzing codebase…")
    try:
        raw = call_llm(system_prompt, user_message)
    except Exception as exc:
        print(f"  [error] master LLM call failed: {exc}")
        return {}

    try:
        result = extract_json(raw)
    except Exception as exc:
        print(f"  [error] master JSON parse failed: {exc}\n{raw[:300]}")
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

    return assignments


# ── per-agent runner ──────────────────────────────────────────────────────────

def run_agent(name: str, context: str, assignment: str | None = None) -> bool:
    print(f"\n{'='*60}")
    print(f"Agent: {name}")
    print(f"{'='*60}")

    agent_file = AGENTS_DIR / f"{name}.md"
    if not agent_file.exists():
        print(f"  [skip] no agent file at {agent_file}")
        return False

    system_prompt = agent_file.read_text(encoding="utf-8")
    if system_prompt.startswith("---"):
        end = system_prompt.find("---", 3)
        if end != -1:
            system_prompt = system_prompt[end + 3:].strip()

    if assignment:
        user_message = (
            f"## Your assigned task for this cycle\n\n"
            f"{assignment}\n\n"
            f"Execute this specific task. Do not pick a different one.\n\n"
            f"## Current codebase\n\n{context}"
        )
    else:
        user_message = f"## Current codebase\n\n{context}"

    print("  Calling LLM…")
    try:
        raw = call_llm(system_prompt, user_message)
    except Exception as exc:
        print(f"  [error] LLM call failed: {exc}")
        return False

    print("  Parsing response…")
    try:
        result = extract_json(raw)
    except Exception as exc:
        print(f"  [error] JSON parse failed: {exc}")
        print(f"  Raw output (first 500 chars):\n{raw[:500]}")
        return False

    task = result.get("task", "improvement")
    files = result.get("files", [])
    commit_msg = result.get("commit_message", f"agent({name}): {task}")

    print(f"  Task  : {task}")
    print(f"  Files : {[f['path'] for f in files]}")

    if not files:
        print("  [skip] no files to write")
        return False

    if DRY_RUN:
        print("  [DRY RUN] would write files and open PR")
        return True

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
        subprocess.run(["git", "checkout", "--", "."], cwd=ROOT)
        return False
    print("  Tests passed ✓")

    # Commit + push
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"agent/{name}-{timestamp}"

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

    pr_url = open_pr(
        branch=branch,
        title=commit_msg,
        body=(
            f"**Agent:** `{name}`\n\n"
            f"**Task:** {task}\n\n"
            f"**Files changed:** {', '.join(f['path'] for f in files)}\n\n"
            f"_Auto-merge enabled — will merge when CI passes._"
        ),
    )
    if pr_url:
        print(f"  PR opened: {pr_url}")

    return True


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Perathos autonomous agent cycle")
    print(f"Time    : {datetime.now(timezone.utc).isoformat()}")
    print(f"Filter  : {AGENT_FILTER}")
    print(f"Dry run : {DRY_RUN}")

    context = build_codebase_context()
    git_log = build_git_log()

    # Single-agent mode: skip master, agent self-selects
    if AGENT_FILTER not in ("all", ""):
        results = {AGENT_FILTER: run_agent(AGENT_FILTER, context)}
    else:
        # Master assigns tasks, then each specialist executes
        assignments = run_master(context, git_log)
        results: dict[str, bool] = {}

        for agent in SPECIALISTS:
            task = assignments.get(agent)
            if task is None and assignments:
                # Master explicitly skipped this agent
                print(f"\n[skip] {agent} — no task assigned by master this cycle")
                results[agent] = True  # not a failure
                continue
            results[agent] = run_agent(agent, context, assignment=task)

    print(f"\n{'='*60}")
    print("Cycle summary")
    print(f"{'='*60}")
    for agent, ok in results.items():
        print(f"  {'✓' if ok else '✗'} {agent}")

    # Exit 0 even on partial failure — partial progress is still progress
    sys.exit(0)


if __name__ == "__main__":
    main()
