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

    Returns:
        Encoding name (e.g., 'utf-8', 'ascii').
    """
    return getattr(sys.stdout, "encoding", None) or "ascii"


def _unicode_ok() -> bool:
    """Check if the terminal can render the Unicode characters we want.

    Returns:
        True if stdout can encode ✓, →, and · characters.
    """
    try:
        "✓→·".encode(_stdout_encoding())
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _short(h: str, n: int = 8) -> str:
    """Truncate a hash to n characters and add ellipsis.

    Args:
        h: Full hash string (typically 64 hex chars).
        n: Number of characters to keep (default 8).

    Returns:
        Truncated hash with "..." appended.
    """
    return f"{h[:n]}..."


def _fmt_ts(issued_at: str) -> str:
    """Format an ISO 8601 timestamp for human display.

    Args:
        issued_at: ISO 8601 timestamp string (e.g., from bundle["issued_at"]).

    Returns:
        Formatted string like "2024-01-15 14:30:45 UTC".
    """
    dt = datetime.fromisoformat(issued_at).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_model(bundle: dict) -> str:
    """Extract and format the model descriptor for display.

    Args:
        bundle: Bundle dict with optional _trace field.

    Returns:
        Human-readable model description (e.g., "sha256-deterministic v1 (perathos-demo-model)").
    """
    descriptor = bundle.get("_trace", {}).get("model_descriptor", bundle.get("proof_system", "unknown"))
    parts = descriptor.split(":")
    if len(parts) == 3:
        name, system, version = parts
        return f"{system} {version} ({name})"
    return descriptor


def _hash_annotation(h: str) -> str:
    """Return annotation string if the hash is special (e.g., empty string).

    Args:
        h: Hash string (typically 64 hex chars).

    Returns:
        Annotation like "  (empty string)" or empty string if normal.
    """
    return "  (empty string)" if h == _EMPTY_HASH else ""


def _steps(bundle: dict) -> list[tuple[int, str, str]]:
    """Extract the hash chain trace steps for display.

    Args:
        bundle: Bundle dict with hash fields.

    Returns:
        List of (step_num, operation_label, short_result) tuples for rendering.
    """
    return [
        (1, "hash_input   ", _short(bundle["input_hash"])),
        (2, "hash_output  ", _short(bundle["output_hash"])),
        (3, "hash_trace   ", _short(bundle["trace_hash"])),
        (4, "integrity    ", _short(bundle["integrity_hash"])),
        (5, "bundle_id    ", f"uuid5({_short(bundle['bundle_id'])})"),
    ]


# ── plain-text renderer ───────────────────────────────────────────────────────────

def _plain(bundle: dict, *, uni: bool) -> None:
    """Render bundle as plain text to stdout.

    Args:
        bundle: Bundle dict to display.
        uni: If True, use Unicode symbols (✓, →, ·); otherwise ASCII (OK, ->, .).
    """
    check = "✓" if uni else "OK"
    arrow = "→" if uni else "->"
    dot   = "·" if uni else "."

    sig = bundle.get("provider_signature")
    sig_line = f"SIGNED ({sig['algorithm']}) {check}" if sig else "UNSIGNED"

    print(f"  Bundle ID : {bundle['bundle_id']}")
    print(f"  Issued    : {_fmt_ts(bundle['issued_at'])}")
    print(f"  Model     : {_fmt_model(bundle)}")
    print(f"  Signature : {sig_line}")

    print()
    print("  Hash Chain")
    for label, key in [("input    ", "input_hash"), ("output   ", "output_hash"),
                       ("trace    ", "trace_hash"), ("integrity", "integrity_hash")]:
        h = bundle[key]
        print(f"    {label} : {_short(h)}{_hash_annotation(h)}")

    print()
    print("  Trace")
    for num, op, result in _steps(bundle):
        print(f"    step {num} {dot} {op} {arrow} {result}")


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
    console.print(f"  [bold]Bundle ID[/bold] : {bundle['bundle_id']}")
    console.print(f"  [bold]Issued[/bold]    : {_fmt_ts(bundle['issued_at'])}")
    console.print(f"  [bold]Model[/bold]     : [cyan]{_fmt_model(bundle)}[/cyan]")

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
        h = bundle[key]
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
