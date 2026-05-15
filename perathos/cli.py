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
)


@click.group()
@click.version_option(version=__version__)
def cli():
    """Perathos — cryptographic proof layer for AI outputs."""


@cli.command()
def keygen():
    """Generate an Ed25519 keypair and save to ~/.perathos/keys/.
    
    Args:
        (none)
    
    Behavior:
        Generates a fresh Ed25519 keypair using libsodium (PyNaCl).
        Saves the signing key (private) to ~/.perathos/keys/signing.key with
        restrictive permissions (0o600 on Unix).
        Saves the verify key (public) to ~/.perathos/keys/verify.key.
        Prints both paths and the public key hex to stdout.
        
        On failure: If keys already exist, exits with code 1 and instructs
        the user to delete the old key manually to rotate.
    
    Example:
        $ perathos keygen
        signing key  /home/user/.perathos/keys/signing.key
        verify key   /home/user/.perathos/keys/verify.key
        verify_key   a1b2c3d4e5f6...(64 hex chars)...
    """
    sk_path = (
        __import__("pathlib").Path.home() / ".perathos" / "keys" / "signing.key"
    )
    if sk_path.exists():
        click.echo(f"Key already exists at {sk_path}")
        click.echo("Delete it manually if you want to rotate keys.")
        sys.exit(1)

    sk_hex, vk_hex = generate_keypair()
    sk_path, vk_path = save_keypair(sk_hex, vk_hex)
    click.echo(f"signing key  {sk_path}")
    click.echo(f"verify key   {vk_path}")
    click.echo(f"verify_key   {vk_hex}")


@cli.command()
@click.argument("text")
@click.option("--input", "input_text", default="", metavar="INPUT",
              help="Original prompt / input that produced TEXT (default: empty). Example: --input 'What is the capital of France?'")
@click.option("--sign", is_flag=True, help="Sign integrity_hash with local Ed25519 key.")
@click.option("--json", "as_json", is_flag=True, help="Print the full bundle JSON.")
def prove_cmd(text: str, input_text: str, sign_flag: bool, as_json: bool):
    """Generate a VRL Proof Bundle for TEXT (treated as AI output).
    
    Args:
        TEXT: The AI-generated text to prove (the output).
        --input INPUT: Optional prompt or request that produced TEXT.
            Defaults to empty string if not provided.
        --sign: If set, signs the bundle's integrity_hash with the local
            Ed25519 signing key (~/.perathos/keys/signing.key).
            Requires keygen to have been run first.
        --json: If set, prints the complete bundle dict as formatted JSON
            to stdout instead of the default human-readable summary.
    
    Behavior:
        Hashes the input and output text, constructs the execution trace,
        and computes the integrity hash. Derives bundle_id deterministically
        from the integrity hash via UUIDv5.
        
        If --sign is set: Loads the local signing key and attaches an Ed25519
        signature over the integrity_hash. Fails with exit code 1 if the key
        is not found (instructs user to run "perathos keygen").
        
        Saves the bundle to ~/.perathos/bundles/{bundle_id}.json.
        
        On success: Prints bundle metadata (bundle_id, ai_id, hashes, timestamp)
        to stdout, plus the file path. If --sign was used, also prints the
        signature summary and verify_key.
        
        On failure: Exits with code 1 if signing key is missing (when --sign
        is used). See Error Handling section of README for interpreting errors.
    
    Example:
        $ perathos prove "The capital of France is Paris."
        bundle_id      550e8400-e29b-41d4-a716-446655440000
        ai_id          abc123def456...
        input_hash     e3b0c442...
        output_hash    c5d9c81d...
        trace_hash     f1a2b3c4...
        integrity_hash 7e8f9a0b...
        issued_at      2024-01-15T14:30:45.123456+00:00
        saved          /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json
        
        $ perathos prove "output text" --input "input text" --sign
        bundle_id      550e8400-e29b-41d4-a716-446655440001
        ai_id          abc123def456...
        ... (hashes) ...
        signature      a1b2c3d4e5f6g7h8...
        verify_key     f9e8d7c6b5a49382...
        saved          /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440001.json
    """
    bundle = prove(output_text=text, input_text=input_text)

    if sign_flag:
        try:
            sk_hex = load_signing_key()
        except FileNotFoundError:
            click.echo("ERROR: No signing key found.", err=True)
            click.echo("Run: perathos keygen", err=True)
            click.echo("Then use: perathos prove TEXT --sign", err=True)
            sys.exit(1)
        bundle = sign(bundle, sk_hex)

    path = save_bundle(bundle)

    if as_json:
        click.echo(json.dumps(bundle, indent=2, sort_keys=True))
        return

    click.echo(f"bundle_id      {bundle['bundle_id']}")
    click.echo(f"ai_id          {bundle['ai_id']}")
    click.echo(f"input_hash     {bundle['input_hash']}")
    click.echo(f"output_hash    {bundle['output_hash']}")
    click.echo(f"trace_hash     {bundle['trace_hash']}")
    click.echo(f"integrity_hash {bundle['integrity_hash']}")
    click.echo(f"issued_at      {bundle['issued_at']}")
    if sign_flag:
        sig = bundle["provider_signature"]
        click.echo(f"signature      {sig['signature'][:32]}…")
        click.echo(f"verify_key     {sig['verify_key']}")
    click.echo(f"saved          {path}")


@cli.command()
@click.argument("bundle_id", required=False)
@click.option("--file", "file_path", type=click.Path(exists=True), metavar="PATH",
              help="Path to a JSON bundle file (instead of bundle_id).")
@click.option("--json", "as_json", is_flag=True, help="Print the full bundle JSON on success.")
def verify_cmd(bundle_id: str, file_path: str, as_json: bool):
    """Verify a VRL Proof Bundle by BUNDLE_ID or from a JSON file.
    
    Args:
        BUNDLE_ID: The UUID of a locally stored bundle (optional if --file is used).
        --file PATH: Path to a JSON bundle file on disk (optional if BUNDLE_ID is used).
            Mutually exclusive with BUNDLE_ID.
        --json: If set, prints the full verified bundle as formatted JSON
            to stdout on success.
    
    Behavior:
        Loads a bundle from local storage (by BUNDLE_ID) or from a file (--file PATH).
        Verifies the hash chain: recomputes trace_hash, integrity_hash, and bundle_id
        from the stored data and checks they match. This step always runs.
        
        If the bundle has a provider_signature field: Also verifies the Ed25519
        signature over the integrity_hash using the verify_key from the signature.
        
        On success (all hashes match, and signature valid if present):
        Prints "VALID_UNSIGNED" or "VALID_SIGNED" to stdout with the bundle identifier.
        If --json is set, also prints the full bundle JSON.
        Exits with code 0.
        
        On failure (hash mismatch or invalid signature):
        Prints "INVALID" followed by the error code (e.g., ERR_TRACE_HASH_MISMATCH
        or ERR_BAD_SIGNATURE) to stderr. See Error Handling section of README
        for error code meanings. Exits with code 1.
        
        On usage error (neither BUNDLE_ID nor --file specified, or both specified):
        Prints error message to stderr. Exits with code 2.
        
        On file not found:
        Prints "ERROR: Bundle not found: <id>" to stderr and suggests "perathos list".
        Exits with code 1.
    
    Example:
        $ perathos verify 550e8400-e29b-41d4-a716-446655440000
        VALID_UNSIGNED  550e8400-e29b-41d4-a716-446655440000
        
        $ perathos verify 550e8400-e29b-41d4-a716-446655440001
        VALID_SIGNED  550e8400-e29b-41d4-a716-446655440001
                      verify_key f9e8d7c6b5a49382...
        
        $ perathos verify --file /tmp/bundle.json
        VALID_UNSIGNED  /tmp/bundle.json
        
        $ perathos verify nonexistent-id
        ERROR: Bundle not found: nonexistent-id
        Run: perathos list
    """
    if file_path and bundle_id:
        click.echo("ERROR: Specify either BUNDLE_ID or --file, not both.", err=True)
        sys.exit(2)

    if not file_path and not bundle_id:
        click.echo("ERROR: Specify either BUNDLE_ID or --file.", err=True)
        sys.exit(2)

    try:
        if file_path:
            bundle = json.loads(Path(file_path).read_text(encoding="utf-8"))
            display_id = file_path
        else:
            bundle = load_bundle(bundle_id)
            display_id = bundle_id
    except FileNotFoundError:
        click.echo(f"ERROR: Bundle not found: {bundle_id}", err=True)
        click.echo("Run: perathos list", err=True)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        click.echo(f"ERROR: Invalid JSON in {file_path}: {exc}", err=True)
        sys.exit(1)

    # Step 1: hash-chain verification (always)
    valid, err = verify(bundle)
    if not valid:
        click.echo(f"INVALID  {err}", err=True)
        sys.exit(1)

    # Step 2: signature verification (only if present)
    if "provider_signature" in bundle:
        sig_valid, sig_err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
        if not sig_valid:
            click.echo(f"INVALID  {sig_err}", err=True)
            sys.exit(1)
        click.echo(f"VALID_SIGNED  {display_id}")
        click.echo(f"              verify_key {bundle['provider_signature']['verify_key']}")
    else:
        click.echo(f"VALID_UNSIGNED  {display_id}")

    if as_json:
        click.echo(json.dumps(bundle, indent=2, sort_keys=True))


@cli.command(name="inspect")
@click.argument("bundle_id")
def inspect_cmd(bundle_id: str):
    """Pretty-print a bundle in human-readable form.
    
    Args:
        BUNDLE_ID: The UUID of a locally stored bundle.
    
    Behavior:
        Loads a bundle from local storage by BUNDLE_ID and displays it
        in human-readable format. Automatically detects terminal capabilities
        and uses rich-styled (colored) output if available and the terminal
        supports Unicode; otherwise falls back to plain text with ASCII symbols.
        
        Displays bundle metadata (ID, issued timestamp, model), signature status,
        hash chain (input, output, trace, integrity), and the trace steps
        (hash_input → hash_output → hash_trace → integrity → bundle_id).
        
        On success: Prints formatted bundle to stdout. No exit code printed.
        Exits with code 0.
        
        On failure: If BUNDLE_ID not found, prints "ERROR: Bundle not found: <id>"
        to stderr and suggests "perathos list". Exits with code 1.
    
    Example:
        $ perathos inspect 550e8400-e29b-41d4-a716-446655440000
          Bundle ID : 550e8400-e29b-41d4-a716-446655440000
          Issued    : 2024-01-15 14:30:45 UTC
          Model     : sha256-deterministic v1 (perathos-demo-model)
          Signature : UNSIGNED
        
          Hash Chain
            input     : e3b0c442...
            output    : c5d9c81d...
            trace     : f1a2b3c4...
            integrity : 7e8f9a0b...
        
          Trace
            step 1 · hash_input   → e3b0c442...
            step 2 · hash_output  → c5d9c81d...
            step 3 · hash_trace   → f1a2b3c4...
            step 4 · integrity    → 7e8f9a0b...
            step 5 · bundle_id    → uuid5(550e8400...)
    """
    try:
        bundle = load_bundle(bundle_id)
    except FileNotFoundError:
        click.echo(f"ERROR: Bundle not found: {bundle_id}", err=True)
        click.echo("Run: perathos list", err=True)
        sys.exit(1)
    inspect(bundle)


@cli.command(name="list")
def list_cmd():
    """List all locally stored bundles.
    
    Args:
        (none)
    
    Behavior:
        Scans ~/.perathos/bundles/ for JSON files and prints the bundle_id
        of each (derived from the filename, without the .json extension).
        Bundles are listed in order of modification time, newest first.
        
        On success: Prints one bundle_id per line to stdout. Exits with code 0.
        
        If no bundles exist: Prints informational message
        "No bundles found in ~/.perathos/bundles/" to stdout.
        Exits with code 0.
    
    Example:
        $ perathos list
        550e8400-e29b-41d4-a716-446655440001
        550e8400-e29b-41d4-a716-446655440000
        a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c
    """
    bundles = list_bundles()
    if not bundles:
        click.echo("No bundles found in ~/.perathos/bundles/")
        return
    for path in bundles:
        click.echo(path.stem)


def main():
    cli()
