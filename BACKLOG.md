# Perathos Product Backlog

Prioritized list of improvements for the autonomous agents loop.
Agents pick one task per cycle, implement it, open a PR.
Mark tasks `[x]` when merged; agents skip completed tasks.

## P0 — Foundation

- [ ] **Public Python API** — expose `prove()`, `verify()`, `sign()`, `inspect()` at the top-level `perathos` package (`__init__.py`). Users should be able to `from perathos import prove` without touching the CLI layer.
- [ ] **stdin support** — `perathos prove -` reads AI output from stdin (pipe-friendly). Also support `--input-file` and `--output-file` flags for file I/O.
- [ ] **`perathos --version`** — print version from `pyproject.toml` metadata (`importlib.metadata`).
- [ ] **Consistent exit codes** — document and enforce: 0=ok, 1=invalid/error, 2=usage error. Currently some paths use `sys.exit(1)` inconsistently.
- [ ] **`perathos verify --file <path>`** — verify a bundle from a JSON file path, not just a stored bundle_id.

## P1 — Features

- [ ] **Batch prove** — `perathos prove --batch <file.jsonl>` reads newline-delimited `{"input": ..., "output": ...}` objects and proves each one. Prints a summary table.
- [ ] **Bundle export/import** — `perathos export <bundle_id>` prints portable JSON to stdout; `perathos import <file.json>` or stdin saves it to local store.
- [ ] **Key rotation** — `perathos keygen --rotate` archives the old key to `signing.key.<timestamp>` and generates a new one without destroying history.
- [ ] **Named keys** — `perathos keygen --name work` stores `work.key` / `work.verify.key`; `perathos prove --key work --sign` selects the named key.
- [ ] **`perathos list --json`** — machine-readable bundle listing (JSON array of bundle metadata).
- [ ] **`perathos list --since <ISO date>`** — filter bundles by date.
- [ ] **Bundle diff** — `perathos diff <id1> <id2>` shows which fields differ between two bundles (useful for comparing outputs across model versions).

## P2 — UX & Polish

- [ ] **Global `--verbose` flag** — show full hashes instead of truncated previews in `prove` and `verify` output.
- [ ] **`perathos inspect --full`** — show all fields including raw `_trace` dict.
- [ ] **Config file** — `~/.perathos/config.toml` for defaults (`default_key`, `bundles_dir`, `sign_by_default`). Read on startup.
- [ ] **TTY auto-detection** — already detects Unicode; also detect `NO_COLOR` env var and `--no-color` flag.
- [ ] **`perathos prove --model <descriptor>`** — override the model descriptor instead of using the hardcoded demo value. First step toward real model identity.
- [ ] **Helpful error messages** — when `keygen` hasn't been run, `prove --sign` should print `Run "perathos keygen" first.` with a non-zero exit.

## P3 — Packaging & Distribution

- [ ] **PyPI release workflow** — `.github/workflows/release.yml` that builds and publishes to PyPI on version tag push. Use `pypa/gh-action-pypi-publish`.
- [ ] **`pip install perathos` smoke test** — add a CI job that installs from `dist/` in a clean venv and runs `perathos --version`.
- [ ] **CHANGELOG.md** — track what changed between versions.
- [ ] **`perathos doctor`** — diagnostic command: checks key presence, bundles dir, Python version, pynacl version. Useful for support.
