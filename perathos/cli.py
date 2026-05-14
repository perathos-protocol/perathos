import json
import sys

import click

from .bundle import create_bundle, sign_bundle, verify_bundle
from .inspector import inspect_bundle
from .signing import generate_keypair, verify_signature
from .storage import (
    list_bundles,
    load_bundle,
    load_signing_key,
    save_bundle,
    save_keypair,
)


@click.group()
def cli():
    """Perathos — cryptographic proof layer for AI outputs."""


@cli.command()
def keygen():
    """Generate an Ed25519 keypair and save to ~/.perathos/keys/."""
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
              help="Original prompt / input that produced TEXT (default: empty).")
@click.option("--sign", is_flag=True, help="Sign integrity_hash with local Ed25519 key.")
@click.option("--json", "as_json", is_flag=True, help="Print the full bundle JSON.")
def prove(text: str, input_text: str, sign: bool, as_json: bool):
    """Generate a VRL Proof Bundle for TEXT (treated as AI output)."""
    bundle = create_bundle(output_text=text, input_text=input_text)

    if sign:
        try:
            sk_hex = load_signing_key()
        except FileNotFoundError as exc:
            click.echo(f"ERROR: {exc}", err=True)
            sys.exit(1)
        bundle = sign_bundle(bundle, sk_hex)

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
    if sign:
        sig = bundle["provider_signature"]
        click.echo(f"signature      {sig['signature'][:32]}…")
        click.echo(f"verify_key     {sig['verify_key']}")
    click.echo(f"saved          {path}")


@cli.command()
@click.argument("bundle_id")
@click.option("--json", "as_json", is_flag=True, help="Print the full bundle JSON on success.")
def verify(bundle_id: str, as_json: bool):
    """Verify a VRL Proof Bundle by BUNDLE_ID."""
    try:
        bundle = load_bundle(bundle_id)
    except FileNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)

    # Step 1: hash-chain verification (always)
    valid, err = verify_bundle(bundle)
    if not valid:
        click.echo(f"INVALID  {err}", err=True)
        sys.exit(1)

    # Step 2: signature verification (only if present)
    if "provider_signature" in bundle:
        sig_valid, sig_err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
        if not sig_valid:
            click.echo(f"INVALID  {sig_err}", err=True)
            sys.exit(1)
        click.echo(f"VALID_SIGNED  {bundle_id}")
        click.echo(f"              verify_key {bundle['provider_signature']['verify_key']}")
    else:
        click.echo(f"VALID_UNSIGNED  {bundle_id}")

    if as_json:
        click.echo(json.dumps(bundle, indent=2, sort_keys=True))


@cli.command(name="inspect")
@click.argument("bundle_id")
def inspect_cmd(bundle_id: str):
    """Pretty-print a bundle in human-readable form."""
    try:
        bundle = load_bundle(bundle_id)
    except FileNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    inspect_bundle(bundle)


@cli.command(name="list")
def list_cmd():
    """List all locally stored bundles."""
    bundles = list_bundles()
    if not bundles:
        click.echo("No bundles found in ~/.perathos/bundles/")
        return
    for path in bundles:
        click.echo(path.stem)


def main():
    cli()
