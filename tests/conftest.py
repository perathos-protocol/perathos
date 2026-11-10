"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def _error_log_in_tmp(monkeypatch, tmp_path_factory):
    """Recording failures are logged to ~/.perathos/errors.log; keep tests out of the real one."""
    monkeypatch.setenv("PERATHOS_ERROR_LOG", str(tmp_path_factory.mktemp("errlog") / "errors.log"))


@pytest.fixture(autouse=True)
def _shell_style_hook_commands(monkeypatch, request):
    """Most install tests compare the classic `perathos-hook record ...` command
    string. Exec-form installs (absolute path + args) are tested explicitly in
    tests/test_v12.py, which opts out with the `exec_hooks` marker."""
    if "exec_hooks" in request.keywords:
        monkeypatch.delenv("PERATHOS_HOOK_COMMAND_STYLE", raising=False)
    else:
        monkeypatch.setenv("PERATHOS_HOOK_COMMAND_STYLE", "shell")
