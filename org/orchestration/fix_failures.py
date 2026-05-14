"""
CI failure auto-fixer for Perathos.

Triggered by the ci-fixer workflow after any failed workflow run.

Steps:
  1. Fetch failed job logs from GitHub API using FAILED_RUN_ID
  2. Build codebase context
  3. Call the ci-fixer agent (Anthropic preferred, OpenRouter fallback)
  4. Parse JSON output (files + commit_message)
  5. Write files, run pytest to validate the fix
  6. Open a PR; GitHub auto-merge closes it when CI passes
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

ROOT = Path(__file__).parent.parent.parent
AGENTS_DIR = ROOT / ".claude" / "agents"

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

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPOSITORY", "")
FAILED_RUN_ID = os.environ.get("FAILED_RUN_ID", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
}


# ── GitHub helpers ────────────────────────────────────────────────────────────

def fetch_failed_logs() -> str:
    """Fetch logs from all failed jobs in the given workflow run."""
    if not FAILED_RUN_ID or not GITHUB_REPO:
        return "(no run ID or repo set — cannot fetch logs)"

    # Get jobs for the run
    resp = httpx.get(
        f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs/{FAILED_RUN_ID}/jobs",
        headers=GH_HEADERS,
        timeout=30,
    )
    if resp.status_code != 200:
        return f"(failed to fetch jobs: {resp.status_code})"

    jobs = resp.json().get("jobs", [])
    failed_jobs = [j for j in jobs if j.get("conclusion") == "failure"]

    if not failed_jobs:
        return "(no failed jobs found in run)"

    all_logs: list[str] = []
    for job in failed_jobs:
        job_id = job["id"]
        job_name = job["name"]

        log_resp = httpx.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/actions/jobs/{job_id}/logs",
            headers=GH_HEADERS,
            timeout=60,
            follow_redirects=True,
        )
        if log_resp.status_code == 200:
            # Trim to last 6000 chars to stay within token budget
            log_text = log_resp.text[-6000:]
            all_logs.append(f"=== Job: {job_name} ===\n{log_text}")
        else:
            all_logs.append(f"=== Job: {job_name} ===\n(could not fetch logs: {log_resp.status_code})")

    return "\n\n".join(all_logs)


# ── Codebase context ──────────────────────────────────────────────────────────

def build_context() -> str:
    parts: list[str] = []
    for rel in SOURCE_FILES:
        path = ROOT / rel
        if path.exists():
            parts.append(f"=== {rel} ===\n{path.read_text(encoding='utf-8')}")
        else:
            parts.append(f"=== {rel} ===\n(file does not exist yet)")
    return "\n\n".join(parts)


# ── LLM ──────────────────────────────────────────────────────────────────────

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
        "temperature": 0.1,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/perathos-protocol/perathos",
        "X-Title": "perathos-ci-fixer",
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
        raise ValueError(f"No JSON found:\n{text[:500]}")
    return json.loads(text[start:end])


# ── Test runner ───────────────────────────────────────────────────────────────

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
        print("  [skip PR] missing GH_TOKEN or GITHUB_REPOSITORY")
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


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Perathos CI auto-fixer")
    print(f"Time     : {datetime.now(timezone.utc).isoformat()}")
    print(f"Run ID   : {FAILED_RUN_ID}")
    print(f"Dry run  : {DRY_RUN}")

    print("\nFetching failure logs…")
    logs = fetch_failed_logs()
    print(f"  {len(logs)} chars of log fetched")

    agent_file = AGENTS_DIR / "ci-fixer.md"
    if not agent_file.exists():
        print(f"[abort] agent file not found: {agent_file}")
        sys.exit(1)

    system_prompt = agent_file.read_text(encoding="utf-8")
    if system_prompt.startswith("---"):
        end = system_prompt.find("---", 3)
        if end != -1:
            system_prompt = system_prompt[end + 3:].strip()

    context = build_context()
    user_message = (
        f"## CI Failure Logs\n\n{logs}\n\n"
        f"## Current Codebase\n\n{context}"
    )

    print("\nCalling LLM…")
    try:
        raw = call_llm(system_prompt, user_message)
    except Exception as exc:
        print(f"[abort] LLM call failed: {exc}")
        sys.exit(1)

    print("Parsing response…")
    try:
        result = extract_json(raw)
    except Exception as exc:
        print(f"[abort] JSON parse failed: {exc}\n{raw[:500]}")
        sys.exit(1)

    task = result.get("task", "")
    files = result.get("files", [])
    commit_msg = result.get("commit_message", "")

    print(f"Task  : {task}")
    print(f"Files : {[f['path'] for f in files]}")

    if not files:
        print("No files to write — transient failure or nothing fixable. Exiting cleanly.")
        sys.exit(0)

    if DRY_RUN:
        print("[DRY RUN] would write files and open PR")
        sys.exit(0)

    # Write files
    for f in files:
        dest = ROOT / f["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f["content"], encoding="utf-8")
        print(f"  wrote {f['path']}")

    # Validate fix locally
    print("Running tests…")
    passed, output = run_tests()
    if not passed:
        print(f"[FAIL] fix broke tests — reverting\n{output[-1000:]}")
        subprocess.run(["git", "checkout", "--", "."], cwd=ROOT)
        sys.exit(1)
    print("Tests passed ✓")

    # Commit + push + PR
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"fix/ci-{timestamp}"

    subprocess.run(["git", "checkout", "-b", branch], cwd=ROOT, check=True)
    subprocess.run(["git", "add", "-A"], cwd=ROOT, check=True)
    subprocess.run(["git", "commit", "-m", commit_msg or f"fix: auto-repair CI failure ({FAILED_RUN_ID})"], cwd=ROOT, check=True)
    subprocess.run(
        ["git", "push", "origin", branch],
        cwd=ROOT,
        env={**os.environ, "GH_TOKEN": GH_TOKEN},
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], cwd=ROOT, check=True)

    pr_url = open_pr(
        branch=branch,
        title=commit_msg or f"fix: auto-repair CI failure",
        body=(
            f"**Agent:** `ci-fixer`\n\n"
            f"**Failed run:** [{FAILED_RUN_ID}](https://github.com/{GITHUB_REPO}/actions/runs/{FAILED_RUN_ID})\n\n"
            f"**Fix:** {task}\n\n"
            f"**Files changed:** {', '.join(f['path'] for f in files)}\n\n"
            f"_Auto-merge enabled — will merge when CI passes._"
        ),
    )
    if pr_url:
        print(f"PR opened: {pr_url}")


if __name__ == "__main__":
    main()
