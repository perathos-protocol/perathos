"""MCP recording proxy: relays unchanged, records tool calls, guards destructive ones."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from perathos.guard import evaluate
from perathos.recorder import session_log_path, verify_session

FAKE_SERVER = textwrap.dedent('''
    import json, sys
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue  # notification
        m, rid = msg.get("method"), msg["id"]
        if m == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}
        elif m == "tools/list":
            res = {"tools": [{"name": "query", "inputSchema": {"type": "object"}}]}
        elif m == "tools/call":
            name = msg["params"]["name"]
            if name == "boom":
                print(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "boom"}}), flush=True)
                continue
            res = {"content": [{"type": "text", "text": "ran " + json.dumps(msg["params"].get("arguments"))}]}
        else:
            res = {}
        print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
''')


@pytest.fixture
def env(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    e = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    subprocess.run([sys.executable, "-m", "perathos", "keygen"], env=e, check=True, capture_output=True)
    vk = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    return e, vk


def _rpc(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m)


def _run_proxy(tmp_path, env, lines, *flags):
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    project = tmp_path / "proj"
    project.mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "perathos", "mcp-proxy", "--name", "db", "--session", "s1",
           "--project", str(project), *flags, "--", sys.executable, str(server)]
    r = subprocess.run(cmd, input="\n".join(lines) + "\n", text=True, capture_output=True, env=env, timeout=60)
    replies = {}
    for line in r.stdout.splitlines():
        if line.strip():
            msg = json.loads(line)
            replies[msg["id"]] = msg
    return r, replies, project


def test_proxy_relays_and_records(tmp_path, env):
    e, vk = env
    lines = [
        _rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _rpc(2, "tools/list"),
        _rpc(3, "tools/call", {"name": "query", "arguments": {"sql": "select count(*) from users"}}),
        _rpc(4, "tools/call", {"name": "boom", "arguments": {}}),
    ]
    r, replies, project = _run_proxy(tmp_path, e, lines)
    assert r.returncode == 0, r.stderr
    assert set(replies) == {1, 2, 3, 4}
    assert replies[2]["result"]["tools"][0]["name"] == "query"
    assert "ran" in replies[3]["result"]["content"][0]["text"]
    assert replies[4]["error"]["message"] == "boom"

    log = session_log_path(project, "s1")
    recs = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    # Calls may overlap (the client pipelines requests), so check per call: the
    # pre receipt precedes its post receipt, and statuses are right.
    pos = {(x["kind"], x.get("tool")): i for i, x in enumerate(recs)}
    assert pos[("pre", "mcp__db__query")] < pos[("post", "mcp__db__query")]
    assert pos[("pre", "mcp__db__boom")] < pos[("post", "mcp__db__boom")]
    status = {x["tool"]: x["status"] for x in recs if x["kind"] == "post"}
    assert status == {"mcp__db__query": "ok", "mcp__db__boom": "error"}
    assert recs[-1]["kind"] == "checkpoint" and recs[-1]["agent"] == "mcp-proxy"
    assert "select count" not in log.read_text(encoding="utf-8")  # hashes only
    rep = verify_session(log, expected_verify_key=vk)
    assert rep.valid, rep.errors
    assert rep.tool_calls == 2


def test_proxy_guard_blocks_sql_inside_arguments(tmp_path, env):
    e, vk = env
    lines = [
        _rpc(1, "tools/call", {"name": "query", "arguments": {"sql": "DROP TABLE users"}}),
        _rpc(2, "tools/call", {"name": "query", "arguments": {"sql": "select 1"}}),
        _rpc(3, "tools/call", {"name": "delete_branch", "arguments": {"branch": "main"}}),
    ]
    r, replies, project = _run_proxy(tmp_path, e, lines, "--guard")
    assert r.returncode == 0, r.stderr
    assert replies[1]["result"]["isError"] is True and "blocked" in replies[1]["result"]["content"][0]["text"]
    assert "ran" in replies[2]["result"]["content"][0]["text"]
    assert replies[3]["result"]["isError"] is True
    rep = verify_session(session_log_path(project, "s1"), expected_verify_key=vk)
    assert rep.valid, rep.errors
    assert rep.blocked == 2 and rep.tool_calls == 3


def test_proxy_periodic_seal(tmp_path, env):
    e, vk = env
    lines = [_rpc(i, "tools/call", {"name": "query", "arguments": {"n": i}}) for i in range(1, 6)]
    r, replies, project = _run_proxy(tmp_path, e, lines, "--seal-every", "2")
    assert r.returncode == 0, r.stderr
    rep = verify_session(session_log_path(project, "s1"), expected_verify_key=vk)
    assert rep.valid, rep.errors
    assert rep.checkpoints == 3  # after 2, after 4, and at the end


def test_guard_scans_mcp_arguments():
    assert evaluate("mcp__supabase__execute_sql", {"query": "drop table orders;"}) is not None
    assert evaluate("mcp__shell__run", {"cmd": "rm -rf /srv/data"}) is not None
    assert evaluate("mcp__supabase__execute_sql", {"query": "select * from orders"}) is None
    m = evaluate("mcp__shell__run", {"cmd": "perathos precondition add --scope x --manual y"})
    assert m is not None and m.self_auth


def test_proxy_with_real_mcp_client_and_server(tmp_path, env):
    """Official MCP client -> perathos mcp-proxy -> real perathos-mcp server."""
    mcp = pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    import anyio

    e, vk = env
    project = tmp_path / "proj"
    project.mkdir()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "perathos", "mcp-proxy", "--name", "perathos", "--session", "real",
              "--project", str(project), "--", sys.executable, "-m", "perathos.mcp_server"],
        env=e,
    )

    async def main():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {t.name for t in tools.tools}
                assert "perathos_verify_answer" in names
                res = await session.call_tool("perathos_verify_answer", {"params": {"answer": "2 + 2 = 4"}})
                assert not res.isError
                return json.loads(res.content[0].text)

    bundle = anyio.run(main)
    assert "integrity_hash" in bundle
    assert mcp is not None
    log = session_log_path(project, "real")
    rep = verify_session(log, expected_verify_key=vk)
    assert rep.valid, rep.errors
    assert rep.tools == {"mcp__perathos__perathos_verify_answer": 1}
