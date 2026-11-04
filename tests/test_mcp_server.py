"""End-to-end tests for the MCP server (perathos/mcp_server.py), driven
through a real in-memory MCP client/server session -- not just calling the
underlying Python functions directly. Requires the optional `mcp` extra
(pip install perathos[mcp]); skipped entirely if it isn't installed.
"""
import json

import pytest

pytest.importorskip("mcp")

from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from perathos.mcp_server import mcp as _mcp_app  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect ~/.perathos to an isolated temp dir for the duration of a test."""
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


@pytest.mark.anyio
async def test_list_tools_exposes_exactly_the_two_expected_tools():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        tools = await client.list_tools()
        names = sorted(t.name for t in tools.tools)
        assert names == ["perathos_verify_answer", "perathos_verify_bundle"]


@pytest.mark.anyio
async def test_verify_answer_flags_wrong_arithmetic():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        result = await client.call_tool(
            "perathos_verify_answer", {"params": {"answer": "The total is 25 * 4 = 999."}}
        )
        assert not result.isError, result.content
        bundle = json.loads(result.content[0].text)
        assert bundle["verdict"] == "FAIL"
        records = bundle["verification"]["verdict_records"]
        symbolic = next(r for r in records if r["verifier_name"] == "Symbolic Solver")
        assert symbolic["verdict"] == "FAIL"
        assert symbolic["computed"] is True


@pytest.mark.anyio
async def test_verify_answer_passes_correct_grounded_arithmetic():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        result = await client.call_tool(
            "perathos_verify_answer",
            {"params": {
                "answer": "The total is 25 * 4 = 100.",
                "sources": ["Invoice: 25 units at $4 each, total $100."],
            }},
        )
        bundle = json.loads(result.content[0].text)
        assert bundle["verdict"] == "PASS"


@pytest.mark.anyio
async def test_verify_bundle_round_trips_a_bundle_from_verify_answer():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        answer_result = await client.call_tool(
            "perathos_verify_answer", {"params": {"answer": "The capital of France is Paris."}}
        )
        bundle_json = answer_result.content[0].text

        # No local signing key in the test env, so the bundle is unsigned:
        # rejected by default, accepted only with an explicit opt-out.
        verify_result = await client.call_tool(
            "perathos_verify_bundle", {"params": {"bundle_json": bundle_json}}
        )
        verdict = json.loads(verify_result.content[0].text)
        assert verdict["valid"] is False and verdict["error_code"] == "ERR_UNSIGNED"

        verify_result = await client.call_tool(
            "perathos_verify_bundle", {"params": {"bundle_json": bundle_json, "allow_unsigned": True}}
        )
        verdict = json.loads(verify_result.content[0].text)
        assert verdict == {"valid": True, "error_code": "", "explanation": ""}


@pytest.mark.anyio
async def test_verify_bundle_rejects_tampering_with_an_explanation():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        answer_result = await client.call_tool(
            "perathos_verify_answer", {"params": {"answer": "The capital of France is Paris."}}
        )
        bundle = json.loads(answer_result.content[0].text)
        bundle["verdict"] = "TAMPERED"

        verify_result = await client.call_tool(
            "perathos_verify_bundle", {"params": {"bundle_json": json.dumps(bundle)}}
        )
        verdict = json.loads(verify_result.content[0].text)
        assert verdict["valid"] is False
        assert verdict["error_code"]
        assert verdict["explanation"]


@pytest.mark.anyio
async def test_verify_answer_signs_when_a_local_key_exists(home):
    from perathos.signing import generate_keypair
    from perathos.storage import save_keypair

    sk_hex, vk_hex = generate_keypair()
    save_keypair(sk_hex, vk_hex)

    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        result = await client.call_tool(
            "perathos_verify_answer", {"params": {"answer": "2 + 2 = 4.", "sign": True}}
        )
        bundle = json.loads(result.content[0].text)
        assert bundle["provider_signature"]["verify_key"] == vk_hex


@pytest.mark.anyio
async def test_verify_answer_stays_unsigned_without_a_local_key(home):
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        result = await client.call_tool(
            "perathos_verify_answer", {"params": {"answer": "2 + 2 = 4.", "sign": True}}
        )
        bundle = json.loads(result.content[0].text)
        assert "provider_signature" not in bundle


@pytest.mark.anyio
async def test_verify_answer_rejects_malformed_json_schema():
    async with create_connected_server_and_client_session(_mcp_app._mcp_server) as client:
        result = await client.call_tool(
            "perathos_verify_answer",
            {"params": {"answer": "some output", "json_schema": "{not valid json"}},
        )
        assert result.isError
