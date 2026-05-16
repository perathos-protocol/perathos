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
    
    Creates a signing key and public verification key for use with --sign.
    
    Example:
        perathos keygen
    """
    sk_path = (
        __import__("pathlib").Path.home() / ".perathos" / "keys" / "signing.key"
    )
    if sk_path.exists():
        click.echo(f"ERROR: Key already exists at {sk_path}", err=True)
        click.echo("Delete it manually if you want to rotate keys.", err=True)
        sys.exit(1)

    sk_hex, vk_hex = generate_keypair()
    sk_path, vk_path = save_keypair(sk_hex, vk_hex)
    click.echo(f"signing key  {sk_path}")
    click.echo(f"verify key   {vk_path}")
    click.echo(f"verify_key   {vk_hex}")


@cli.command()
@click.argument("text")
@click.option("--input", "input_text", default="", metavar="INPUT",
              help="Original prompt / input that produced TEXT. Example: --input 'What is the capital of France?'")
@click.option("--sign", is_flag=True, 
              help="Sign integrity_hash with local Ed25519 key (run: perathos keygen first).")
@click.option("--json", "as_json", is_flag=True, 
              help="Print the full bundle as JSON. Example: perathos prove 'output' --json")
def prove_cmd(text: str, input_text: str, sign_flag: bool, as_json: bool):
    """Generate a VRL Proof Bundle for TEXT (AI-generated output).
    
    TEXT is the AI-generated output you want to prove. --input specifies the optional
    original prompt or request that produced TEXT.
    
    Examples:
        perathos prove "The capital of France is Paris."
        perathos prove "The answer is 42." --input "What is the answer?"
        perathos prove "Hello world." --sign --json
    """
    bundle = prove(output_text=text, input_text=input_text)

    if sign_flag:
        try:
            sk_hex = load_signing_key()
        except FileNotFoundError:
            click.echo("ERROR: Signing key not found.", err=True)
            click.echo("Run: perathos keygen", err=True)
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
              help="Path to a JSON bundle file. Example: --file bundle.json")
@click.option("--json", "as_json", is_flag=True, 
              help="Print the full bundle as JSON on success. Example: perathos verify <id> --json")
def verify_cmd(bundle_id: str, file_path: str, as_json: bool):
    """Verify a VRL Proof Bundle by BUNDLE_ID or from a JSON file.
    
    Verify stored bundle by its UUID, or load and verify from a JSON file.
    Exit code 0 = valid, 1 = invalid, 2 = usage error.
    
    Examples:
        perathos verify 550e8400-e29b-41d4-a716-446655440000
        perathos verify --file bundle.json
        perathos verify 550e8400-e29b-41d4-a716-446655440000 --json
    """
    if file_path and bundle_id:
        click.echo("ERROR: Use either BUNDLE_ID or --file, not both.", err=True)
        click.echo("Example: perathos verify 550e8400-e29b-41d4-a716-446655440000", err=True)
        click.echo("Example: perathos verify --file bundle.json", err=True)
        sys.exit(2)

    if not file_path and not bundle_id:
        click.echo("ERROR: Specify either BUNDLE_ID or --file.", err=True)
        click.echo("Run: perathos verify --help", err=True)
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
        click.echo(f"Ensure the file contains valid JSON.", err=True)
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
    
    Example:
        perathos inspect 550e8400-e29b-41d4-a716-446655440000
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
    
    Example:
        perathos list
    """
    bundles = list_bundles()
    if not bundles:
        click.echo("No bundles found in ~/.perathos/bundles/")
        return
    for path in bundles:
        click.echo(path.stem)


def main():
    cli()
