"""Human-readable bundle inspection with rich/plain dual rendering.

Provides pretty-printed visual representation of bundles, with rich colored
output when available and a clean plain-text fallback. Automatically detects
Unicode support and gracefully degrades on limited terminals.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

# SHA-256("") — shown as "(empty string)" in the hash chain
_EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _stdout_encoding() -> str:
    """Get the encoding of stdout, defaulting to ASCII.

    Returns the encoding name that stdout is configured to use. This is used
    to determine whether the terminal can render Unicode characters. If stdout
    does not have an encoding attribute, defaults to ASCII (a safe fallback
    for environments where encoding info is unavailable).

    Returns:
        Encoding name (e.g., 'utf-8', 'ascii').
    """
    return getattr(sys.stdout, "encoding", None) or "ascii"


def _unicode_ok() -> bool:
    """Check if the terminal can render the Unicode characters we want.

    Tests whether stdout can encode the specific Unicode characters used by
    Perathos for pretty-printing: ✓ (checkmark), → (arrow), and · (bullet).
    If the terminal cannot render these, the function returns False and the
    plain-text ASCII fallback renderer is used instead.

    Returns:
        True if stdout can encode ✓, →, and · characters; False otherwise.
    """
    try:
        "✓→·".encode(_stdout_encoding())
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _safe_conf_pct(value) -> float:
    """confidence_bps (0..1000) -> percent, tolerant of non-numeric junk."""
    try:
        return float(value) / 10.0
    except (TypeError, ValueError):
        return 0.0


def _safe_ev_count(value) -> int:
    return len(value) if isinstance(value, (list, tuple)) else 0


def _short(h: str, n: int = 8) -> str:
    """Truncate a hash to n characters and add ellipsis.

    Useful for displaying long hashes (e.g., 64-character SHA-256 digests)
    in a human-readable format. By default shows first 8 characters plus "..."
    for brevity in terminal output.

    Args:
        h: Full hash string (typically 64 hex chars).
        n: Number of characters to keep (default 8).

    Returns:
        Truncated hash with "..." appended.
    """
    return f"{str(h)[:n]}..."


def _fmt_ts(issued_at: str) -> str:
    """Format an ISO 8601 timestamp for human display.

    Converts an ISO 8601 timestamp string (as stored in bundle["issued_at"])
    into a human-friendly format: "YYYY-MM-DD HH:MM:SS UTC".

    Args:
        issued_at: ISO 8601 timestamp string (e.g., from bundle["issued_at"]).

    Returns:
        Formatted string like "2024-01-15 14:30:45 UTC".
    """
    try:
        dt = datetime.fromisoformat(str(issued_at)).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return str(issued_at)


def _fmt_model(bundle: dict) -> str:
    """Extract and format the model descriptor for display.

    Reads the model descriptor from bundle["_trace"]["model_descriptor"],
    parses its colon-separated components, and formats them for human display.
    Falls back to proof_system if model_descriptor is unavailable.

    Args:
        bundle: Bundle dict with optional _trace field.

    Returns:
        Human-readable model description (e.g., "sha256-deterministic v1 (perathos-demo-model)").
    """
    # Robust against a _trace that is missing, None, or not even a dict, and a
    # model_descriptor that is not a string — inspect must never crash on a
    # hand-edited or foreign bundle.
    trace = bundle.get("_trace")
    descriptor = trace.get("model_descriptor") if isinstance(trace, dict) else None
    if descriptor is None:
        descriptor = bundle.get("proof_system", "unknown")
    descriptor = str(descriptor)
    parts = descriptor.split(":")
    if len(parts) == 3:
        name, system, version = parts
        return f"{system} {version} ({name})"
    return descriptor


def _hash_annotation(h: str) -> str:
    """Return annotation string if the hash is special (e.g., empty string).

    Checks if a hash matches the special SHA-256(empty string) value and returns
    an annotation explaining what it represents. Used to help readers understand
    why certain hashes appear in the chain (e.g., when input text is empty).

    Args:
        h: Hash string (typically 64 hex chars).

    Returns:
        Annotation like "  (empty string)" or empty string if normal.
    """
    return "  (empty string)" if h == _EMPTY_HASH else ""


def _steps(bundle: dict) -> list[tuple[int, str, str]]:
    """Extract the hash chain trace steps for display.

    Reads the hash fields from a bundle and formats them as a list of
    (step_num, operation_label, short_result) tuples suitable for rendering
    the hash chain trace in the inspector output.

    Args:
        bundle: Bundle dict with hash fields.

    Returns:
        List of (step_num, operation_label, short_result) tuples for rendering.
    """
    return [
        (1, "hash_input   ", _short(bundle.get("input_hash", ""))),
        (2, "hash_output  ", _short(bundle.get("output_hash", ""))),
        (3, "hash_trace   ", _short(bundle.get("trace_hash", ""))),
        (4, "integrity    ", _short(bundle.get("integrity_hash", ""))),
        (5, "bundle_id    ", f"uuid5({_short(bundle.get('bundle_id', ''))})"),
    ]


# ── plain-text renderer ───────────────────────────────────────────────────────────

def _plain(bundle: dict, *, uni: bool) -> None:
    """Render bundle as plain text to stdout.

    Outputs a human-readable bundle representation using plain ASCII or
    Unicode characters (if terminal supports them). No colors or styling,
    suitable for terminals without rich/ANSI support.

    Args:
        bundle: Bundle dict to display.
        uni: If True, use Unicode symbols (✓, →, ·); otherwise ASCII (OK, ->, .).
    """
    check = "✓" if uni else "OK"
    arrow = "→" if uni else "->"
    dot   = "·" if uni else "."

    sig = bundle.get("provider_signature")
    sig_line = f"SIGNED ({sig['algorithm']}) {check}" if sig else "UNSIGNED"

    print(f"  Bundle ID : {bundle.get('bundle_id', '(missing)')}")
    print(f"  Issued    : {_fmt_ts(bundle.get('issued_at', ''))}")
    print(f"  Model     : {_fmt_model(bundle)}")
    print(f"  Signature : {sig_line}")

    print()
    print("  Hash Chain")
    for label, key in [("input    ", "input_hash"), ("output   ", "output_hash"),
                       ("trace    ", "trace_hash"), ("integrity", "integrity_hash")]:
        h = bundle.get(key, "")
        print(f"    {label} : {_short(h)}{_hash_annotation(h)}")

    print()
    print("  Trace")
    for num, op, result in _steps(bundle):
        print(f"    step {num} {dot} {op} {arrow} {result}")

    verification = bundle.get("verification")
    if isinstance(verification, dict):
        agg = verification.get("aggregate")
        agg = agg if isinstance(agg, dict) else {}
        records = verification.get("verdict_records")
        records = records if isinstance(records, list) else []
        print()
        print("  Verification")
        print(f"    aggregate : {agg.get('verdict', '?')} ({agg.get('rationale', '')})")
        for rec in records:
            if not isinstance(rec, dict):
                continue
            conf = _safe_conf_pct(rec.get("confidence_bps"))
            ev = _safe_ev_count(rec.get("evidence_digests"))
            print(f"    {dot} [{rec.get('verifier_id')}] {rec.get('verifier_name')}: "
                  f"{rec.get('verdict')} (conf {conf:.0f}%, {ev} evidence) {arrow} {rec.get('detail', '')}")


# ── rich renderer ─────────────────────────────────────────────────────────────────

def _rich(bundle: dict) -> None:
    """Render bundle using rich library for colored, styled output.

    Requires the 'rich' package to be installed.
    Uses VT100 mode to ensure proper Unicode rendering on all platforms.

    Args:
        bundle: Bundle dict to display.
    """
    from rich.console import Console
    from rich.text import Text

    # Force VT100 mode to avoid the legacy Windows cp1252 renderer.
    # We only reach this path when _unicode_ok() confirmed the terminal
    # can handle our characters, so no further encoding guard needed.
    console = Console(legacy_windows=False)

    sig = bundle.get("provider_signature")

    console.print()
    console.print(Text(f"  Bundle ID : {bundle.get('bundle_id', '(missing)')}"))
    console.print(Text(f"  Issued    : {_fmt_ts(bundle.get('issued_at', ''))}"))
    console.print(Text(f"  Model     : {_fmt_model(bundle)}", style="cyan"))

    if sig:
        t = Text("  Signature : ")
        t.append(f"SIGNED ({sig['algorithm']}) ✓", style="bold green")
        console.print(t)
    else:
        t = Text("  Signature : ")
        t.append("UNSIGNED", style="yellow")
        console.print(t)

    console.print()
    console.print("  [bold]Hash Chain[/bold]")
    for label, key in [("input    ", "input_hash"), ("output   ", "output_hash"),
                       ("trace    ", "trace_hash"), ("integrity", "integrity_hash")]:
        h = bundle.get(key, "")
        row = Text(f"    {label} : ")
        row.append(_short(h), style="dim cyan")
        ann = _hash_annotation(h)
        if ann:
            row.append(ann, style="dim")
        console.print(row)

    console.print()
    console.print("  [bold]Trace[/bold]")
    for num, op, result in _steps(bundle):
        row = Text(f"    step {num} ")
        row.append("·", style="dim")
        row.append(f" {op} ")
        row.append("→", style="dim")
        row.append(f" {result}", style="dim cyan")
        console.print(row)

    verification = bundle.get("verification")
    if isinstance(verification, dict):
        agg = verification.get("aggregate")
        agg = agg if isinstance(agg, dict) else {}
        records = verification.get("verdict_records")
        records = records if isinstance(records, list) else []
        verdict = str(agg.get("verdict", "?"))
        color = {"PASS": "green", "FAIL": "red", "WARN": "yellow"}.get(verdict, "cyan")
        console.print()
        console.print("  [bold]Verification[/bold]")
        agg_row = Text("    aggregate : ")
        agg_row.append(verdict, style=f"bold {color}")
        agg_row.append(f"  {agg.get('rationale', '')}", style="dim")
        console.print(agg_row)
        for rec in records:
            if not isinstance(rec, dict):
                continue
            conf = _safe_conf_pct(rec.get("confidence_bps"))
            ev = _safe_ev_count(rec.get("evidence_digests"))
            # Text.append() renders literally — verifier_name/detail can never be
            # parsed as rich markup, so a crafted '[/bold]' cannot raise.
            row = Text(f"    · [{rec.get('verifier_id')}] {rec.get('verifier_name')}: ")
            row.append(str(rec.get("verdict")), style="bold")
            row.append(f" (conf {conf:.0f}%, {ev} evidence) → {rec.get('detail', '')}", style="dim")
            console.print(row)

    console.print()


# ── public entry point ────────────────────────────────────────────────────────────

def inspect_bundle(bundle: dict) -> None:
    """Pretty-print a bundle in human-readable form.

    Automatically selects between rich-styled output (if rich is installed and
    terminal supports Unicode) and plain-text fallback. Displays bundle metadata,
    hash chain, and trace steps with appropriate styling.

    Args:
        bundle: Bundle dict from create_bundle() or loaded via storage.load_bundle().
    """
    uni = _unicode_ok()
    try:
        import rich  # noqa: F401
        if uni:
            _rich(bundle)
            return
    except ImportError:
        pass
    _plain(bundle, uni=uni)
