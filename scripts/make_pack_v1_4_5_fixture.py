"""Rebuild tests/fixtures/pack_v1_4_5 with real perathos 1.4.5 code.

The fixture is a session recorded and exported by 1.4.5 (before `guard.gate`
existed): a plain block, a precondition allow, a Gate request left pending, a
Gate denial and a Gate approval. tests/test_evidence.py checks that this code
still verifies the pack and re-exports the log with the same verdict.

    mkdir v145 && git archive v1.4.5 | tar -x -C v145
    python -I scripts/make_pack_v1_4_5_fixture.py v145 tests/fixtures/pack_v1_4_5

Keys and timestamps are fresh on every run, so a rebuild is equivalent, not
byte-identical. Only public keys are written. The 1.4.5 tree (its perathos
package and its tests/test_gate.py stub Gate) must be the one imported; the
script checks that.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

V145 = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(V145))
work = Path(tempfile.mkdtemp(prefix="v145-"))
os.environ["USERPROFILE"] = os.environ["HOME"] = str(work / "home")
for v in (
    "PERATHOS_GATE_URL",
    "PERATHOS_GATE_API_KEY",
    "PERATHOS_GATE_KEY",
    "PERATHOS_SIGNER",
    "CI",
    "GITHUB_ACTIONS",
    "PERATHOS_GATE_SHOW_LINK",
    "PERATHOS_GATE_APPROVERS",
):
    os.environ.pop(v, None)

import perathos  # noqa: E402

assert str(V145) in perathos.__file__, (
    f"imported {perathos.__file__}, not the 1.4.5 tree"
)
assert perathos.__version__ == "1.4.5", perathos.__version__
from click.testing import CliRunner  # noqa: E402

from perathos.cli import cli  # noqa: E402
from perathos.evidence import export_evidence_pack  # noqa: E402
from perathos.gate import apply_gate  # noqa: E402
from perathos.guard import create_precondition, decide  # noqa: E402
from perathos.recorder import record_hook_event, session_log_path  # noqa: E402
from perathos.signing import generate_keypair  # noqa: E402
from tests.test_gate import ARGS, DENY, StubGate  # noqa: E402

SID = "v145"
project = work / "proj"
project.mkdir()
sk, vk = generate_keypair()
g = StubGate()
r = CliRunner().invoke(
    cli, ["gate", "login", "--url", g.url, "--api-key", "key-1", "--wait", "5"]
)
assert r.exit_code == 0, r.output


def pre(tid, guard, args):
    record_hook_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": SID,
            "cwd": str(project),
            "tool_name": "Bash",
            "tool_use_id": tid,
            "tool_input": args,
        },
        guard_decision=guard,
    )


cmd = {"command": "terraform destroy -auto-approve"}
pre(
    "t1", decide("Bash", cmd, project, trusted_key=vk).receipt_field(), cmd
)  # plain block
create_precondition(
    project, scope="*", signing_key_hex=sk, manual_reason="snapshot checked"
)
pre(
    "t2", decide("Bash", cmd, project, trusted_key=vk).receipt_field(), cmd
)  # precondition allow
pre(
    "t3",
    apply_gate(
        DENY, tool="Bash", args=ARGS, cwd=project, wait_seconds=0
    ).receipt_field(),
    ARGS,
)  # pending
g.decide(g.only_pending(), "deny")
pre(
    "t4",
    apply_gate(
        DENY, tool="Bash", args=ARGS, cwd=project, wait_seconds=0
    ).receipt_field(),
    ARGS,
)  # denied
apply_gate(DENY, tool="Bash", args=ARGS, cwd=project, wait_seconds=0)
g.decide(g.only_pending(), "approve")
pre(
    "t5",
    apply_gate(
        DENY, tool="Bash", args=ARGS, cwd=project, wait_seconds=0
    ).receipt_field(),
    ARGS,
)  # approved
record_hook_event(
    {"hook_event_name": "Stop", "session_id": SID, "cwd": str(project)},
    signing_key_hex=sk,
)
res = export_evidence_pack(
    session_log_path(project, SID), work / "evidence-pack", signing_key_hex=sk
)
assert res["valid"], res["report"]["errors"]
g.close()

if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir(parents=True)
# The 1.4.5 project state (log, head, approvals, preconditions) and the pack 1.4.5 exported from it.
shutil.copytree(
    project / ".perathos",
    OUT / "project" / ".perathos",
    ignore=shutil.ignore_patterns("pending.json", "*.used"),
)
shutil.copyfile(res["zip"], OUT / "evidence-pack.zip")
(OUT / ".gitattributes").write_text(
    "# Made by perathos 1.4.5: keep the bytes exactly as written, on every OS.\n"
    "* -text\n",
    encoding="utf-8",
)
approver = json.loads(
    next((OUT / "project/.perathos/approvals").glob("apr_*.json")).read_text("utf-8")
)["approver"]
(OUT / "keys.json").write_text(
    json.dumps(
        {
            "made_by": "perathos 1.4.5 (git archive v1.4.5), scripts/make_pack_v1_4_5_fixture.py",
            "session_id": SID,
            "signer_verify_key": vk,
            "gate_key": g.server_vk,
            "approver_public_key": approver["public_key"],
            "report_1_4_5": {
                k: res["report"][k] for k in ("valid", "blocked", "tool_calls")
            },
        },
        indent=2,
    ),
    encoding="utf-8",
)
print(
    "ok",
    OUT,
    sorted(p.relative_to(OUT).as_posix() for p in OUT.rglob("*") if p.is_file()),
)
shutil.rmtree(work, ignore_errors=True)
