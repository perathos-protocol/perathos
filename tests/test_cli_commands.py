"""End-to-end tests that drive the click commands themselves.

The other CLI tests exercise only helper functions (_format_hash, _explain_error)
and never invoke the `prove`/`verify`/`keygen` commands through click. That gap
let a regression ship in which `perathos prove` crashed on *every* invocation
with `TypeError: prove_cmd() got an unexpected keyword argument 'sign'`, because
the `--sign` flag's click-derived parameter name did not match the function
signature. These tests invoke the commands via click's CliRunner so that class
of bug is caught.
"""
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect ~/.perathos to an isolated temp dir for the duration of a test."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def test_prove_unsigned_succeeds(home):
    """`prove` with no flags must run and save a bundle (would catch the kwarg bug)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["prove", "The capital of France is Paris."])
    assert result.exit_code == 0, result.output
    assert "bundle_id" in result.output


def test_prove_signed_succeeds(home):
    """`prove --sign` must run end to end after keygen (the exact broken path)."""
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    result = runner.invoke(cli, ["prove", "Paris is the capital of France.", "--sign"])
    assert result.exit_code == 0, result.output
    assert "signature" in result.output


def test_prove_then_verify_roundtrip(home):
    """A signed bundle written to a file must verify as VALID_SIGNED."""
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    out_file = str(home / "bundle.json")
    prove = runner.invoke(
        cli, ["prove", "2 + 2 = 4", "--sign", "--output-file", out_file, "--quiet"]
    )
    assert prove.exit_code == 0, prove.output
    verify = runner.invoke(cli, ["verify", "--file", out_file])
    assert verify.exit_code == 0, verify.output
    assert "VALID_SIGNED" in verify.output


def test_verify_detects_tampering(home):
    """Mutating output_hash must break verification (the core tamper-evidence claim)."""
    import json

    runner = CliRunner()
    out_file = home / "bundle.json"
    prove = runner.invoke(
        cli, ["prove", "The answer is 42.", "--output-file", str(out_file), "--quiet"]
    )
    assert prove.exit_code == 0, prove.output

    bundle = json.loads(out_file.read_text(encoding="utf-8"))
    first = bundle["output_hash"][0]
    bundle["output_hash"] = ("b" if first == "a" else "a") + bundle["output_hash"][1:]
    out_file.write_text(json.dumps(bundle), encoding="utf-8")

    verify = runner.invoke(cli, ["verify", "--file", str(out_file)])
    assert verify.exit_code == 1
    assert "INVALID" in verify.output
