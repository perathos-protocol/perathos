import json
import sys
from pathlib import Path

import click

from . import __version__, prove, sign, verify, inspect
from .signing import generate_keypair, verify_signature
from .storage import (
    list_bundles,
    load_bundle,
    load_signing_key,
    save_bundle,
    save_keypair,
    keys_dir,
)


# Error code explanations
_ERROR_EXPLANATIONS = {
    "ERR_MISSING_TRACE": "Bundle is missing execution metadata (_trace field). The bundle file may be corrupted or truncated. Next step: Check the bundle file with 'python -m json.tool <bundle_path>' to validate JSON syntax.",
    "ERR_TRACE_HASH_MISMATCH": "Execution metadata was tampered with. The hash chain is broken — the _trace field doesn't match trace_hash. Next step: Do not trust this bundle. Verify the source and obtain the original bundle from the provider.",
    "ERR_INTEGRITY_HASH_MISMATCH": "Bundle fields (ai_id, input_hash, output_hash, issued_at, or trace_hash) were tampered with. The bundle has been modified since creation. Next step: Do not trust this bundle. This is a critical tamper detection.",
    "ERR_BUNDLE_ID_MISMATCH": "Bundle ID was manually changed or corrupted. The bundle_id field doesn't match the integrity_hash. Next step: Do not trust this bundle. Verify the source and obtain the original bundle from the provider.",
    "ERR_BAD_SIGNATURE": "Cryptographic signature is invalid. The bundle or signature was modified after signing, or the signing key is incorrect. Next step: Verify the provider's public key and ask them to confirm the bundle hasn't been modified.",
    "ERR_MISSING_FIELD": "Bundle is missing a required field. The bundle structure is invalid or corrupted. Next step: Check the bundle file with 'python -m json.tool <bundle_path>' to see which fields are present.",
    "ERR_NO_SIGNING_KEY": "Signing key not found. To generate a keypair, run: perathos keygen. Then sign your bundle with: perathos prove '<output_text>' --sign",
    "ERR_INPUT_FILE_NOT_FOUND": "Input file not found. Check that the file exists and the path is correct. Example: perathos prove 'output' --input-file prompt.txt",
    "ERR_INPUT_FILE_READ": "Failed to read input file. Check that the file is readable and not corrupted. Example: perathos prove 'output' --input-file prompt.txt",
}


def _explain_error(error_code: str) -> str:
    """Return human-readable explanation for an error code.
    
    Maps error codes (e.g., "ERR_TRACE_HASH_MISMATCH") to user-friendly explanations
    with actionable next steps. Handles error codes with suffixes (e.g., 
    "ERR_MISSING_FIELD:output_hash") by extracting the base code and adding field-specific
    context. Returns the original error code if no explanation exists.
    
    Args:
        error_code: Error code string (e.g., "ERR_TRACE_HASH_MISMATCH" or "ERR_MISSING_FIELD:output_hash").
    
    Returns:
        Human-readable explanation string with next steps, or the original error code if unmapped.
    
    Examples:
        _explain_error("ERR_TRACE_HASH_MISMATCH")
        → "Execution metadata was tampered with. The hash chain is broken — ..."
        
        _explain_error("ERR_MISSING_FIELD:output_hash")
        → "Bundle is missing a required field: output_hash. The bundle structure is invalid..."
    """
    # Handle error codes with suffixes (e.g., "ERR_MISSING_FIELD:output_hash")
    base_code = error_code.split(":")[0]
    
    if base_code in _ERROR_EXPLANATIONS:
        explanation = _ERROR_EXPLANATIONS[base_code]
        # For ERR_MISSING_FIELD, add field name to the explanation
        if base_code == "ERR_MISSING_FIELD" and ":" in error_code:
            field_name = error_code.split(":", 1)[1]
            explanation = f"Bundle is missing required field: {field_name}. The bundle structure is invalid or corrupted. Next step: Check the bundle file with 'python -m json.tool <bundle_path>' to see which fields are present."
        return explanation
    
    return error_code


def _format_hash(h: str, verbose: bool) -> str:
    """Format a hash for display based on verbosity setting.
    
    In normal mode, truncates to first 8 characters with ellipsis for compact output.
    In verbose mode, displays the full hash (typically 64 hex characters for SHA-256).
    
    Args:
        h: Full hash string (typically 64 hex chars).
        verbose: If True, show full hash; if False, show first 8 chars with ellipsis.
    
    Returns:
        Formatted hash string (either full or truncated with "...").
    """
    if verbose:
        return h
    return f"{h[:8]}..."


def _list_available_bundles() -> str:
    """Return a formatted string listing all available bundles.
    
    Scans the local bundles directory and formats the list of stored bundle UUIDs.
    If no bundles exist, suggests how to create one with the prove command.
    
    Returns:
        A formatted string with bundle list, or a message if no bundles exist.
    """
    bundles = list_bundles()
    if not bundles:
        return "No bundles found. To create a bundle, run:\n  perathos prove '<output_text>'"
    lines = ["Available bundles:"]
    for path in bundles:
        lines.append(f"  {path.stem}")
    return "\n".join(lines)


@click.group()
@click.version_option(version=__version__)
def cli():
    """Perathos — cryptographic proof layer for AI outputs."""


@cli.command()
def keygen():
    """Generate an Ed25519 keypair and save to ~/.perathos/keys/.
    
    Creates a signing key and public verification key for use with --sign.
    The keypair is stored locally:
        signing.key   (private key, protected with mode 0o600)
        verify.key    (public key)
    
    After keygen, sign and prove bundles with:
        perathos prove '<output_text>' --sign
    
    Example:
        perathos keygen
        perathos prove 'Hello world.' --sign
    """
    sk_path = keys_dir() / "signing.key"
    vk_path = keys_dir() / "verify.key"
    if sk_path.exists():
        click.echo(f"[ERROR] Keypair already exists at {keys_dir()}", err=True)
        click.echo("", err=True)
        click.echo("To regenerate, delete the old keys and run keygen again:", err=True)
        click.echo(f"  rm {sk_path} {vk_path}", err=True)
        click.echo("  perathos keygen", err=True)
        click.echo("", err=True)
        click.echo("Warning: This will invalidate all bundles signed with the old key.", err=True)
        sys.exit(1)

    sk_hex, vk_hex = generate_keypair()
    sk_path, vk_path = save_keypair(sk_hex, vk_hex)
    click.echo(f"signing.key (PRIVATE — keep secret) {sk_path}")
    click.echo(f"verify.key (PUBLIC — can be shared)  {vk_path}")
    click.echo(f"verify_key (public; shareable)       {vk_hex}")
    click.echo("")
    click.echo("✓ Keypair saved. To sign bundles, run:")
    click.echo("  perathos prove '<output_text>' --sign")


@cli.command()
@click.argument("text", required=False)
@click.option("--input", "input_text", default="", metavar="INPUT",
              help="Original prompt / input that produced TEXT. Example: --input 'What is the capital of France?'")
@click.option("--input-file", type=click.Path(exists=False), metavar="PATH",
              help="Read input_text from file instead of --input. Example: --input-file prompt.txt")
@click.option("--output-file", type=click.Path(), metavar="PATH",
              help="Write bundle JSON to file instead of saving to ~/.perathos/bundles/. Example: --output-file bundle.json")
@click.option("--sign", "sign_flag", is_flag=True,
              help="Sign integrity_hash with local Ed25519 key (requires: perathos keygen). Example: perathos prove 'output' --sign")
@click.option("--json", "as_json", is_flag=True, 
              help="Print the full bundle as JSON. Example: perathos prove 'output' --json")
@click.option("--verbose", is_flag=True,
              help="Display full 64-character hashes instead of truncated 8-character previews.")
@click.option("--quiet", "-q", is_flag=True,
              help="Suppress bundle output; only print the saved file path. Useful for scripting. Ignored if --json is used.")
def prove_cmd(text: str, input_text: str, input_file: str, output_file: str, sign_flag: bool, as_json: bool, verbose: bool, quiet: bool):
    """Generate a VRL Proof Bundle for TEXT (AI-generated output).
    
    Creates an unsigned proof bundle by default. Add --sign to attach an Ed25519
    cryptographic signature (requires running 'perathos keygen' first).
    
    TEXT is the AI-generated output you want to prove. If TEXT is '-', reads from stdin.
    Specify --input to include the optional original prompt or request that produced TEXT.
    Both prove modes (signed and unsigned) produce a tamper-evident bundle stored locally
    by default (unless --output-file is specified).
    
    Examples:
        perathos prove "The capital of France is Paris."
            → Creates an UNSIGNED proof bundle
        
        perathos prove - < output.txt
            → Reads output from stdin, creates UNSIGNED bundle
        
        perathos prove "The answer is 42." --input "What is the answer?"
            → UNSIGNED bundle with input prompt included
        
        perathos prove "Hello world." --sign
            → Creates a SIGNED proof bundle (requires keygen)
        
        perathos prove "Output text." --input-file prompt.txt --sign
            → Reads input from file, creates SIGNED bundle
        
        perathos prove - --input-file prompt.txt --output-file bundle.json
            → Reads output from stdin, input from file, writes bundle to file
    """
    # Handle TEXT and stdin reading
    if text is None:
        click.echo("[ERROR] TEXT argument is required.", err=True)
        click.echo("Provide output text directly or use '-' to read from stdin.", err=True)
        click.echo("", err=True)
        click.echo("Examples:", err=True)
        click.echo("  perathos prove 'The capital of France is Paris.'", err=True)
        click.echo("  perathos prove - < output.txt  (read from stdin)", err=True)
        click.echo("  perathos prove 'output' --input 'prompt'", err=True)
        sys.exit(2)
    
    if text == "-":
        text = sys.stdin.read()
    
    # Handle input_text: --input and --input-file are mutually exclusive
    if input_text and input_file:
        click.echo("[ERROR] --input and --input-file are mutually exclusive. Use one or the other.", err=True)
        click.echo("", err=True)
        click.echo("Choose one of:", err=True)
        click.echo("  --input 'text'            (provide inline text)", err=True)
        click.echo("  --input-file path         (read from file)", err=True)
        click.echo("", err=True)
        click.echo("Examples:", err=True)
        click.echo("  perathos prove 'output' --input 'What is the capital?'", err=True)
        click.echo("  perathos prove 'output' --input-file prompt.txt", err=True)
        sys.exit(2)
    
    if input_file:
        try:
            input_text = Path(input_file).read_text(encoding="utf-8")
        except FileNotFoundError:
            click.echo(f"[ERROR] Input file not found: {input_file}", err=True)
            click.echo("", err=True)
            click.echo("Check that the file exists and the path is correct.", err=True)
            click.echo(f"Example: perathos prove 'output' --input-file {input_file}", err=True)
            sys.exit(1)
        except OSError as exc:
            click.echo(f"[ERROR] Failed to read input file: {exc}", err=True)
            click.echo("", err=True)
            click.echo("Check that the file is readable and not corrupted.", err=True)
            click.echo(f"Example: perathos prove 'output' --input-file {input_file}", err=True)
            sys.exit(1)
    
    bundle = prove(output_text=text, input_text=input_text)

    if sign_flag:
        try:
            sk_hex = load_signing_key()
        except FileNotFoundError:
            click.echo("[ERROR] Signing key not found.", err=True)
            click.echo("", err=True)
            click.echo("To generate a keypair, run:", err=True)
            click.echo("  perathos keygen", err=True)
            click.echo("", err=True)
            click.echo("Then sign your bundle with:", err=True)
            click.echo("  perathos prove '<output_text>' --sign", err=True)
            sys.exit(1)
        bundle = sign(bundle, sk_hex)

    # Handle output: --output-file or default save_bundle()
    if output_file:
        try:
            Path(output_file).write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
            saved_path = output_file
        except OSError as exc:
            click.echo(f"[ERROR] Failed to write output file: {exc}", err=True)
            sys.exit(1)
    else:
        saved_path = str(save_bundle(bundle))

    if as_json:
        click.echo(json.dumps(bundle, indent=2, sort_keys=True))
        return

    if quiet:
        click.echo(saved_path)
        return

    click.echo(f"bundle_id      {_format_hash(bundle['bundle_id'], verbose)}")
    click.echo(f"ai_id          {_format_hash(bundle['ai_id'], verbose)}")
    click.echo(f"input_hash     {_format_hash(bundle['input_hash'], verbose)}")
    click.echo(f"output_hash    {_format_hash(bundle['output_hash'], verbose)}")
    click.echo(f"trace_hash     {_format_hash(bundle['trace_hash'], verbose)}")
    click.echo(f"integrity_hash {_format_hash(bundle['integrity_hash'], verbose)}")
    click.echo(f"issued_at      {bundle['issued_at']}")
    if sign_flag:
        sig = bundle["provider_signature"]
        sig_display = _format_hash(sig['signature'], verbose)
        click.echo(f"signature      {sig_display}")
        vk_display = _format_hash(sig['verify_key'], verbose)
        click.echo(f"verify_key     {vk_display}")
    click.echo(f"saved          {saved_path}")


@cli.command()
@click.argument("bundle_id", required=False)
@click.option("--file", "file_path", type=click.Path(exists=True), metavar="PATH",
              help="Path to a JSON bundle file. Example: --file bundle.json")
@click.option("--json", "as_json", is_flag=True, 
              help="Print the full bundle as JSON on success. Example: perathos verify <id> --json")
@click.option("--verbose", is_flag=True,
              help="Display full 64-character hashes instead of truncated 8-character previews.")
def verify_cmd(bundle_id: str, file_path: str, as_json: bool, verbose: bool):
    """Verify a VRL Proof Bundle by BUNDLE_ID or from a JSON file.
    
    Verifies the integrity chain (hash chain) of a stored bundle using its UUID,
    or loads and verifies a bundle from an external JSON file via --file.
    
    Exit codes:
        0 = Bundle is valid (hash chain verified, signature valid if present)
        1 = Bundle is invalid (tamper detection, hash mismatch, bad signature)
        2 = Usage error (missing arguments, conflicting options)
    
    For stored bundles: Use BUNDLE_ID (the bundle's UUID).
    For external JSON files: Use --file <path> instead of BUNDLE_ID.
    
    Examples:
        perathos verify 550e8400-e29b-41d4-a716-446655440000
            → Verify a stored bundle by its UUID
        
        perathos verify --file /path/to/exported_bundle.json
            → Verify a bundle from a JSON file (e.g., exported from another system)
        
        perathos verify 550e8400-e29b-41d4-a716-446655440000 --json
            → Verify and display full bundle JSON on success
    """
    if file_path and bundle_id:
        click.echo("[ERROR] Use either BUNDLE_ID or --file, not both.", err=True)
        click.echo("", err=True)
        click.echo("To verify a stored bundle, omit --file:", err=True)
        click.echo("  perathos verify <bundle_id>", err=True)
        click.echo("", err=True)
        click.echo("To verify a file, omit BUNDLE_ID:", err=True)
        click.echo("  perathos verify --file bundle.json", err=True)
        sys.exit(2)

    if not file_path and not bundle_id:
        click.echo("[ERROR] Specify either BUNDLE_ID or --file.", err=True)
        click.echo("", err=True)
        click.echo("To verify a stored bundle:", err=True)
        click.echo("  perathos verify <bundle_id>", err=True)
        click.echo("", err=True)
        click.echo("To verify a file:", err=True)
        click.echo("  perathos verify --file bundle.json", err=True)
        sys.exit(2)

    try:
        if file_path:
            bundle = json.loads(Path(file_path).read_text(encoding="utf-8"))
            display_id = file_path
        else:
            bundle = load_bundle(bundle_id)
            display_id = bundle_id
    except FileNotFoundError:
        click.echo(f"[ERROR] Bundle not found: {bundle_id}", err=True)
        click.echo("", err=True)
        click.echo("Next step: List your bundles with:", err=True)
        click.echo("  perathos list", err=True)
        click.echo("", err=True)
        available = _list_available_bundles()
        if "No bundles" in available:
            click.echo(available, err=True)
            click.echo("  Example: perathos prove 'The answer is 42.'", err=True)
        else:
            click.echo(available, err=True)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        click.echo(f"[ERROR] Invalid JSON in {file_path}: {exc}", err=True)
        click.echo("", err=True)
        click.echo("Next step: Validate the file syntax with:", err=True)
        click.echo(f"  python -m json.tool {file_path}", err=True)
        click.echo("", err=True)
        click.echo("Fix any syntax errors and try again.", err=True)
        sys.exit(1)

    # Step 1: hash-chain verification (always)
    valid, err = verify(bundle)
    if not valid:
        explanation = _explain_error(err)
        click.echo(f"[ERROR] INVALID  {err}", err=True)
        click.echo(f"Reason: {explanation}", err=True)
        sys.exit(1)

    # Step 2: signature verification (only if present)
    if "provider_signature" in bundle:
        sig_valid, sig_err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
        if not sig_valid:
            explanation = _explain_error(sig_err)
            click.echo(f"[ERROR] INVALID  {sig_err}", err=True)
            click.echo(f"Reason: {explanation}", err=True)
            sys.exit(1)
        click.echo(f"VALID_SIGNED  {display_id}")
        vk_display = _format_hash(bundle['provider_signature']['verify_key'], verbose)
        click.echo(f"              verify_key {vk_display}")
    else:
        click.echo(f"VALID_UNSIGNED  {display_id}")

    if as_json:
        click.echo(json.dumps(bundle, indent=2, sort_keys=True))


@cli.command(name="inspect")
@click.argument("bundle_id")
def inspect_cmd(bundle_id: str):
    """Pretty-print a bundle in human-readable form.
    
    Displays bundle metadata, hash chain, and trace steps with automatic
    styling (Unicode symbols if terminal supports them, plain ASCII fallback).
    
    Example:
        perathos inspect 550e8400-e29b-41d4-a716-446655440000
    """
    try:
        bundle = load_bundle(bundle_id)
    except FileNotFoundError:
        click.echo(f"[ERROR] Bundle not found: {bundle_id}", err=True)
        click.echo("", err=True)
        click.echo("Next step: List your bundles with:", err=True)
        click.echo("  perathos list", err=True)
        sys.exit(1)
    inspect(bundle)


@cli.command(name="list")
def list_cmd():
    """List all locally stored bundles.
    
    Displays all bundles in ~/.perathos/bundles/, newest first.
    Shows the bundle_id (UUID) of each stored bundle.
    
    Example:
        perathos list
    """
    bundles = list_bundles()
    if not bundles:
        click.echo("No bundles found in ~/.perathos/bundles/")
        click.echo("")
        click.echo("To create a new bundle, run:")
        click.echo("  perathos prove '<output_text>'")
        return
    for path in bundles:
        click.echo(path.stem)


def main():
    cli()
