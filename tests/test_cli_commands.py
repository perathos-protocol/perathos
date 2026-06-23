"""End-to-end tests that drive the click commands themselves.

The other CLI tests exercise only helper functions (_format_hash, _explain_error)
and never invoke the `prove`/`verify`/`keygen` commands through click. That gap
let a regression ship in which `perathos prove` crashed on *every* invocation
with `TypeError: prove_cmd() got an unexpected keyword argument 'sign'`, because
the `--sign` flag's click-derived parameter name did not match the function
signature. These tests invoke the commands via click's CliRunner so that class
of bug is caught.
"""
import json
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


def test_keygen_output_is_cp1252_safe(home, monkeypatch):
    """keygen must not emit characters that crash a Windows cp1252 console.

    CliRunner backs stdout with UTF-8, so it cannot reproduce the cp1252 crash
    directly. Instead we force the no-Unicode branch and assert the output
    encodes cleanly to cp1252 (the bug was an unguarded U+2713 checkmark).
    """
    monkeypatch.setattr("perathos.cli._unicode_ok", lambda: False)
    runner = CliRunner()
    result = runner.invoke(cli, ["keygen"])
    assert result.exit_code == 0, result.output
    result.output.encode("cp1252")  # must not raise UnicodeEncodeError


def test_inspect_command(home):
    runner = CliRunner()
    prove = runner.invoke(cli, ["prove", "Inspect me.", "--quiet"])
    assert prove.exit_code == 0, prove.output
    bundle_id = prove.output.strip().splitlines()[-1]
    bundle_id = Path(bundle_id).stem
    result = runner.invoke(cli, ["inspect", bundle_id])
    assert result.exit_code == 0, result.output
    assert "Bundle ID" in result.output


def test_list_command(home):
    runner = CliRunner()
    assert runner.invoke(cli, ["prove", "One.", "--quiet"]).exit_code == 0
    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0, result.output
    assert len(result.output.strip()) > 0


def test_verify_with_pinned_key(home):
    """verify --verify-key accepts the matching signer and rejects a wrong one."""
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    verify_key = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()

    out_file = str(home / "b.json")
    assert runner.invoke(
        cli, ["prove", "Pinned.", "--sign", "--output-file", out_file, "--quiet"]
    ).exit_code == 0

    ok = runner.invoke(cli, ["verify", "--file", out_file, "--verify-key", verify_key])
    assert ok.exit_code == 0, ok.output
    assert "VALID_SIGNED" in ok.output

    wrong = "f" * 64
    bad = runner.invoke(cli, ["verify", "--file", out_file, "--verify-key", wrong])
    assert bad.exit_code == 1
    assert "INVALID" in bad.output


def test_prove_with_evidence_runs_verification(home):
    """`prove --evidence-text` runs the pipeline and binds a verdict."""
    runner = CliRunner()
    out_file = str(home / "v.json")
    r = runner.invoke(cli, [
        "prove", "The capital of France is Paris.",
        "--evidence-text", "The capital of France is Paris, its largest city.",
        "--output-file", out_file,
    ])
    assert r.exit_code == 0, r.output
    assert "verdict" in r.output
    bundle = json.loads(Path(out_file).read_text(encoding="utf-8"))
    assert "verification" in bundle
    # the bound verification survives offline verification
    verify = runner.invoke(cli, ["verify", "--file", out_file])
    assert verify.exit_code == 0, verify.output


def test_prove_with_samples_runs_verification(home):
    runner = CliRunner()
    r = runner.invoke(cli, [
        "prove", "The sky is blue.",
        "--sample-text", "The sky is blue.",
        "--sample-text", "The sky appears blue.",
        "--json",
    ])
    assert r.exit_code == 0, r.output
    bundle = json.loads(r.output)
    ids = [rec["verifier_id"] for rec in bundle["verification"]["verdict_records"]]
    assert 122 in ids  # Cross-Examiner ran


def test_doctor_runs(home):
    r = CliRunner().invoke(cli, ["doctor"])
    assert r.exit_code == 0, r.output
    assert "perathos" in r.output
    assert "python" in r.output


def test_require_signed_policy(home):
    runner = CliRunner()
    out_file = str(home / "u.json")
    runner.invoke(cli, ["prove", "x", "--output-file", out_file, "--quiet"])
    # unsigned bundle is valid but fails the signed policy gate
    ok = runner.invoke(cli, ["verify", "--file", out_file])
    assert ok.exit_code == 0
    policy = runner.invoke(cli, ["verify", "--file", out_file, "--require-signed"])
    assert policy.exit_code == 1
    assert "POLICY" in policy.output


def test_require_pass_policy(home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    # A bundle whose bound verdict is not PASS must fail --require-pass.
    out_file = str(home / "berlin.json")
    runner.invoke(cli, [
        "prove", "The capital of France is Paris.",  # lexical: supported -> PASS path
        "--sample-text", "totally unrelated nonsense alpha",
        "--sample-text", "more unrelated nonsense beta",
        "--output-file", out_file, "--quiet",
    ])
    bundle = json.loads(Path(out_file).read_text(encoding="utf-8"))
    verdict = bundle["verification"]["aggregate"]["verdict"]
    r = runner.invoke(cli, ["verify", "--file", out_file, "--require-pass"])
    if verdict == "PASS":
        assert r.exit_code == 0
    else:
        assert r.exit_code == 1
        assert "POLICY" in r.output


def test_version_is_current():
    from perathos import __version__
    r = CliRunner().invoke(cli, ["--version"])
    assert __version__ in r.output
    assert r.output.strip().endswith("0.2.1")


def test_verify_trust_jwks(home):
    from perathos.keytrust import LocalSigner, TrustStore
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    out_file = str(home / "s.json")
    assert runner.invoke(cli, ["prove", "x", "--sign", "--output-file", out_file, "--quiet"]).exit_code == 0

    vk_hex = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    trusted = str(home / "jwks.json")
    Path(trusted).write_text(json.dumps(TrustStore().add_public_key(bytes.fromhex(vk_hex)).to_jwks()), encoding="utf-8")
    ok = runner.invoke(cli, ["verify", "--file", out_file, "--trust-jwks", trusted])
    assert ok.exit_code == 0, ok.output

    untrusted = str(home / "other.json")
    Path(untrusted).write_text(json.dumps(TrustStore().add_signer(LocalSigner.generate()).to_jwks()), encoding="utf-8")
    bad = runner.invoke(cli, ["verify", "--file", out_file, "--trust-jwks", untrusted])
    assert bad.exit_code == 1
    assert "INVALID" in bad.output
