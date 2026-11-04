import json
import sys
from pathlib import Path

import click

from . import __version__, prove, sign, verify, inspect
from .errors import explain_error as _explain_error
from .inspector import _unicode_ok
from .pipeline import CONJUNCTION, QUORUM, verify_output
from .signing import generate_keypair
from .verifiers import ClaimEntailmentVerifier, CrossExaminer, VerificationContext
from .storage import (
    list_bundles,
    load_bundle,
    load_signing_key,
    save_bundle,
    save_keypair,
    keys_dir,
)


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
    # Guard the checkmark: a raw U+2713 crashes with UnicodeEncodeError on a
    # Windows cp1252 console (the key is already written by this point, which
    # made the tool look permanently broken on every subsequent keygen).
    mark = "✓ " if _unicode_ok() else ""
    click.echo(f"{mark}Keypair saved. To sign bundles, run:")
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
@click.option("--evidence", "evidence_files", multiple=True, type=click.Path(exists=True), metavar="PATH",
              help="Evidence document file for claim-entailment verification (repeatable). Example: --evidence doc1.txt --evidence doc2.txt")
@click.option("--evidence-text", "evidence_texts", multiple=True, metavar="TEXT",
              help="Inline evidence document for claim-entailment verification (repeatable).")
@click.option("--sample", "sample_files", multiple=True, type=click.Path(exists=True), metavar="PATH",
              help="A re-sampled model output file for self-consistency verification (repeatable).")
@click.option("--sample-text", "sample_texts", multiple=True, metavar="TEXT",
              help="An inline re-sampled model output for self-consistency verification (repeatable).")
@click.option("--nli", "use_nli", is_flag=True,
              help="Use the real NLI model for claim entailment (requires: pip install perathos[nli]). Default is the lexical verifier.")
@click.option("--schema", "schema_file", type=click.Path(exists=True), default=None, metavar="PATH",
              help="JSON Schema file the answer must conform to (runs the schema-validator engine).")
@click.option("--mode", "agg_mode", type=click.Choice([CONJUNCTION, QUORUM]), default=CONJUNCTION,
              help="Aggregation mode for the multi-verifier pipeline. Default: conjunction (any FAIL fails).")
@click.option("--model", "model_id", default="unspecified", metavar="ID",
              help="Model id recorded in the bundle (v2 top-level field).")
@click.option("--include-answer", is_flag=True,
              help="Store the answer text verbatim in the bundle (default: hash only).")
@click.option("--json", "as_json", is_flag=True,
              help="Print the full bundle as JSON. Example: perathos prove 'output' --json")
@click.option("--verbose", is_flag=True,
              help="Display full 64-character hashes instead of truncated 8-character previews.")
@click.option("--quiet", "-q", is_flag=True,
              help="Suppress bundle output; only print the saved file path. Useful for scripting. Ignored if --json is used.")
def prove_cmd(text: str, input_text: str, input_file: str, output_file: str, sign_flag: bool,
              evidence_files: tuple, evidence_texts: tuple, sample_files: tuple, sample_texts: tuple,
              use_nli: bool, schema_file: str, agg_mode: str, model_id: str, include_answer: bool,
              as_json: bool, verbose: bool, quiet: bool):
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
    
    # Assemble verification evidence (files + inline) and run the pipeline if
    # any was supplied. Otherwise, a plain proof bundle.
    evidence = list(evidence_texts)
    for p in evidence_files:
        try:
            evidence.append(Path(p).read_text(encoding="utf-8"))
        except OSError as exc:
            click.echo(f"[ERROR] Failed to read evidence file {p}: {exc}", err=True)
            sys.exit(1)
    samples = list(sample_texts)
    for p in sample_files:
        try:
            samples.append(Path(p).read_text(encoding="utf-8"))
        except OSError as exc:
            click.echo(f"[ERROR] Failed to read sample file {p}: {exc}", err=True)
            sys.exit(1)

    schema_dict = None
    if schema_file:
        try:
            schema_dict = json.loads(Path(schema_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            click.echo(f"[ERROR] Could not read --schema file {schema_file}: {exc}", err=True)
            sys.exit(1)

    if evidence or samples or use_nli or schema_dict is not None:
        entailment_fn = None
        if use_nli:
            try:
                from .verifiers_nli import nli_entailment_fn
                entailment_fn = nli_entailment_fn()
            except ImportError:
                click.echo("[ERROR] NLI requires the NLI extra. Install it with:", err=True)
                click.echo("  pip install perathos[nli]", err=True)
                click.echo("", err=True)
                click.echo("Then try again:", err=True)
                click.echo("  perathos prove 'your output' --nli", err=True)
                sys.exit(1)
        if evidence and not use_nli:
            click.echo(
                "[note] claim entailment is using the deterministic LEXICAL verifier, "
                "which only measures word overlap and cannot tell, e.g., Paris from "
                "Berlin. For a real NLI model use --nli (pip install perathos[nli]).",
                err=True,
            )
        # Full verifier suite: the two pipeline verifiers + the real engines.
        # Engines with nothing to check return NOT_APPLICABLE (excluded from the
        # aggregate), so running them all is always safe.
        from .engines import all_engines
        verifiers = [CrossExaminer(), ClaimEntailmentVerifier(entailment_fn=entailment_fn)] + all_engines()
        # --evidence feeds both claim-entailment (evidence) and the extractive
        # grounding engine (sources).
        ctx = VerificationContext(samples=samples, evidence=evidence, sources=evidence, schema=schema_dict)
        bundle = verify_output(text, input_text, verifiers=verifiers, context=ctx, mode=agg_mode,
                               model=model_id, include_answer=include_answer)
    else:
        bundle = prove(output_text=text, input_text=input_text,
                       model=model_id, include_answer=include_answer)

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
    if "verification" in bundle:
        agg = bundle["verification"].get("aggregate", {})
        click.echo(f"verdict        {agg.get('verdict', '?')} ({agg.get('rationale', '')})")
    click.echo(f"saved          {saved_path}")


@cli.command()
@click.argument("bundle_id", required=False)
@click.option("--file", "file_path", type=click.Path(exists=True), metavar="PATH",
              help="Path to a JSON bundle file. Example: --file bundle.json")
@click.option("--json", "as_json", is_flag=True, 
              help="Print the full bundle as JSON on success. Example: perathos verify <id> --json")
@click.option("--verbose", is_flag=True,
              help="Display full 64-character hashes instead of truncated 8-character previews.")
@click.option("--verify-key", "expected_verify_key", default=None, metavar="HEX",
              help="Pin the expected signer: accept a signed bundle only if its public key matches this 64-char hex key. Prevents silent signer substitution.")
@click.option("--require-signed", is_flag=True, hidden=True,
              help="Deprecated no-op: signatures are now required by default.")
@click.option("--allow-unsigned", is_flag=True,
              help="Accept an unsigned bundle (hash-chain consistency only). Unsigned bundles fail by default because anyone can create one.")
@click.option("--require-pass", is_flag=True,
              help="Policy gate: exit non-zero unless the bound verification aggregate verdict is PASS.")
@click.option("--trust-jwks", "trust_jwks", type=click.Path(exists=True), default=None, metavar="PATH",
              help="Verify the signer against a trusted key set (JWKS file). Rejects any signer whose key is not in the set.")
def verify_cmd(bundle_id: str, file_path: str, as_json: bool, verbose: bool, expected_verify_key: str,
               require_signed: bool, allow_unsigned: bool, require_pass: bool, trust_jwks: str):
    """Verify a VRL Proof Bundle by BUNDLE_ID or from a JSON file.
    
    Verifies the integrity chain (hash chain) of a stored bundle using its UUID,
    or loads and verifies a bundle from an external JSON file via --file.
    
    Exit codes:
        0 = Bundle is valid (hash chain verified and signature valid)
        1 = Bundle is invalid (tamper detection, hash mismatch, bad signature,
            or unsigned without --allow-unsigned)
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
    if require_signed and allow_unsigned:
        click.echo("[ERROR] --require-signed and --allow-unsigned conflict.", err=True)
        sys.exit(2)

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

    # Optional trust anchor: verify the signer's key is in a trusted JWKS set.
    trust_store = None
    if trust_jwks:
        from .keytrust import TrustStore
        try:
            trust_store = TrustStore.from_jwks(json.loads(Path(trust_jwks).read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            click.echo(f"[ERROR] Invalid JSON in JWKS file {trust_jwks}: {exc}", err=True)
            click.echo("", err=True)
            click.echo("JWKS must be valid JSON with a 'keys' array. Example:", err=True)
            click.echo(json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "ed25519-...", "x": "..."}]}, indent=2), err=True)
            sys.exit(2)
        except ValueError as exc:
            click.echo(f"[ERROR] Invalid JWKS file {trust_jwks}: {exc}", err=True)
            click.echo("", err=True)
            click.echo("Check that the file is valid JSON with a 'keys' array of OKP/Ed25519 entries:", err=True)
            click.echo(json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "ed25519-xxx", "x": "base64url-encoded-public-key"}]}, indent=2), err=True)
            sys.exit(2)

    # Step 1: hash-chain + signature verification (verify() also validates the
    # provider_signature when present, pins the signer if --verify-key given,
    # and checks the trust store if --trust-jwks given)
    valid, err = verify(bundle, expected_verify_key=expected_verify_key, trust_store=trust_store)
    if not valid:
        explanation = _explain_error(err)
        click.echo(f"[ERROR] INVALID  {err}", err=True)
        click.echo(f"Reason: {explanation}", err=True)
        sys.exit(1)

    # Step 2: policy gates (a deployment may require signed + PASS in one call).
    # The bundle is already cryptographically valid at this point, so any present
    # signature has validated and any bound verdict is tamper-evident.
    if not allow_unsigned and "provider_signature" not in bundle:
        click.echo("[ERROR] UNSIGNED  bundle has no signature, so its issuer is unproven", err=True)
        click.echo(f"Reason: {_explain_error('ERR_UNSIGNED')}", err=True)
        sys.exit(1)
    if require_pass:
        verification = bundle.get("verification")
        agg = verification.get("aggregate", {}) if isinstance(verification, dict) else {}
        verdict = agg.get("verdict")
        if verdict != "PASS":
            click.echo(f"[ERROR] POLICY  verification verdict is {verdict!r}, but --require-pass requires PASS", err=True)
            sys.exit(1)

    # Step 3: report
    if "provider_signature" in bundle:
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


@cli.command()
def doctor():
    """Diagnose the local Perathos environment.

    Reports Python/package versions, optional-extra availability (NLI),
    key presence, and the bundle store — useful for support and CI smoke tests.
    Exit code 0 if the core is healthy, 1 if a core dependency is missing.
    """
    import platform
    import sys as _sys

    ok = True

    def line(label, value, good=True):
        nonlocal ok
        mark = ("✓" if _unicode_ok() else "[ok]") if good else ("✗" if _unicode_ok() else "[!!]")
        if not good:
            ok = False
        click.echo(f"  {mark} {label:22} {value}")

    click.echo("Perathos doctor")
    line("perathos", __version__)
    line("python", platform.python_version())

    try:
        import cryptography
        line("cryptography", getattr(cryptography, "__version__", "installed"))
    except ImportError:
        line("cryptography", "MISSING — pip install cryptography", good=False)

    try:
        import click as _click
        line("click", _click.__version__)
    except Exception:  # pragma: no cover
        line("click", "unknown")

    # Optional NLI extra
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        line("nli extra", "available")
    except ImportError:
        click.echo(f"  {'-' } nli extra              not installed (pip install perathos[nli]) — optional")

    # Keys
    sk = keys_dir() / "signing.key"
    vk = keys_dir() / "verify.key"
    if sk.exists() and vk.exists():
        line("signing key", str(sk))
    else:
        click.echo(f"  {'-'} signing key            none (run: perathos keygen) — optional, only needed for --sign")

    # Bundle store
    try:
        n = len(list_bundles())
        line("bundle store", f"{n} bundle(s)")
    except OSError as exc:  # pragma: no cover
        line("bundle store", f"error: {exc}", good=False)

    if not ok:
        _sys.exit(1)


@cli.command(name="cite-check")
@click.argument("path", type=click.Path(exists=True, dir_okay=False), required=False)
@click.option("--text", "text", default=None, help="Check this inline text instead of a file.")
@click.option("--prove", "prove_flag", is_flag=True,
              help="Emit a Proof Bundle binding the citation verdict + corpus_hash (re-verifiable offline).")
@click.option("--sign", "sign_flag", is_flag=True, help="Sign the proof bundle (implies --prove; requires: perathos keygen).")
@click.option("--out", "out_path", type=click.Path(dir_okay=False), default=None, help="Write the proof bundle JSON here.")
def cite_check(path, text, prove_flag, sign_flag, out_path):
    """Check the U.S. legal citations in a brief/output for fabrication.

    Deterministically verifies that cited authorities exist and are attributed to
    the right case, against a pinned, content-addressed public case-law snapshot
    (no network). FAILs on fabrication evidence; reports INCONCLUSIVE — never a
    false flag — for citations outside the snapshot's coverage.

    With --prove it emits a signed, tamper-evident Proof Bundle that binds the
    verdict and the corpus_hash, so a counterparty can re-verify it offline.

    Examples:
        perathos cite-check brief.txt
        perathos cite-check brief.txt --sign --out brief.bundle.json
    """
    from .legal import CitationVerifier

    if text is None:
        if path is None:
            click.echo("[ERROR] provide a PATH or --text", err=True)
            sys.exit(2)
        text = Path(path).read_text(encoding="utf-8", errors="replace")

    verifier = CitationVerifier()
    record = verifier.run(text, VerificationContext())
    ev = record.evidence or {}

    click.echo(f"verdict:     {record.verdict}")
    click.echo(f"detail:      {record.detail}")
    if ev:
        click.echo(f"corpus:      {ev.get('corpus_version')}")
        click.echo(f"corpus_hash: {ev.get('corpus_hash')}")
        click.echo(f"rules:       {ev.get('engine_rules_version')}")
        click.echo("citations:")
        for c in ev.get("citations", []):
            mark = {"fabricated": "FAIL", "misattributed": "FAIL",
                    "grounded": "ok", "out_of_coverage": "?"}.get(c["status"], "?")
            reason = c.get("reason") or c.get("resolved_name") or ""
            click.echo(f"  [{mark:>4}] {c['raw']}  ({c['status']}) {reason}")

    if prove_flag or sign_flag or out_path:
        # Bind the citation verdict (and the corpus_hash inside it) into a Proof
        # Bundle's integrity_hash via the standard verification block.
        bundle = verify_output(text, verifiers=[CitationVerifier()], model="perathos-cite-check")
        if sign_flag:
            sk_hex = load_signing_key()
            if not sk_hex:
                click.echo("[ERROR] No signing key. Run: perathos keygen", err=True)
                sys.exit(2)
            from .bundle import sign_bundle
            bundle = sign_bundle(bundle, sk_hex)
        click.echo("")
        click.echo(f"bundle_id:   {bundle['bundle_id']}")
        click.echo(f"signed:      {'yes' if 'provider_signature' in bundle else 'no'}")
        if out_path:
            Path(out_path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            click.echo(f"written:     {out_path}  (verify offline: perathos verify --file {out_path})")

    # Exit non-zero on a fabrication so the command is usable as a gate.
    if record.verdict == "FAIL":
        sys.exit(1)


@cli.group()
def hooks():
    """Manage the Claude Code Stop-hook integration."""


_STOP_CHECK_CMD = "perathos hooks stop-check"
_RECORD_CMD = "perathos hooks record"
_RECORDER_EVENTS = ("PreToolUse", "PostToolUse", "Stop", "SessionEnd")
_TOOL_EVENTS = ("PreToolUse", "PostToolUse")


def _entry_commands(entry) -> list[str]:
    """Commands in one settings entry, in either the nested or the old flat shape."""
    if not isinstance(entry, dict):
        return []
    cmds = [str(entry.get("command", ""))] if "command" in entry else []
    for h in entry.get("hooks") or []:
        if isinstance(h, dict):
            cmds.append(str(h.get("command", "")))
    return cmds


def _is_perathos_entry(entry, command: str) -> bool:
    """True if the entry runs this perathos command, with or without flags."""
    base = command.split(" --")[0]
    return any(c == base or c.startswith(base + " ") for c in _entry_commands(entry))


def _is_perathos_stop_hook(entry) -> bool:
    return _is_perathos_entry(entry, _STOP_CHECK_CMD)


def _load_settings(settings_path: Path) -> dict:
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            click.echo(f"[ERROR] {settings_path} is not valid JSON: {exc}", err=True)
            click.echo("Fix or remove it, then re-run this command.", err=True)
            sys.exit(1)
        if not isinstance(settings, dict):
            click.echo(f"[ERROR] {settings_path} does not contain a JSON object.", err=True)
            sys.exit(1)
    return settings


def _add_hook(hooks_block: dict, event: str, command: str, timeout: int, force: bool, settings_path: Path) -> None:
    """Add one command hook in Claude Code's nested shape.

    {"EventName": [{"matcher": "*", "hooks": [{"type": "command", ...}]}]}.
    Older perathos versions wrote a flat {"type": "command"} entry, which
    Claude Code does not run; those are removed and replaced here.
    """
    entries = hooks_block.setdefault(event, [])
    flat_legacy = [e for e in entries if _is_perathos_entry(e, command) and "hooks" not in e]
    existing = [e for e in entries if _is_perathos_entry(e, command) and "hooks" in e]
    if existing and not force:
        click.echo(f"[ERROR] A perathos {event} hook is already installed in {settings_path}.", err=True)
        click.echo("Use --force to reinstall.", err=True)
        sys.exit(1)
    if existing or flat_legacy:
        entries[:] = [e for e in entries if not _is_perathos_entry(e, command)]
    entry: dict = {"hooks": [{"type": "command", "command": command, "timeout": timeout}]}
    if event in _TOOL_EVENTS:
        entry = {"matcher": "*", **entry}
    entries.append(entry)


@hooks.command(name="install")
@click.option("--scope", type=click.Choice(["project", "user"]), default="project",
              help="Install into .claude/settings.json (project, default) or ~/.claude/settings.json (user).")
@click.option("--force", is_flag=True, help="Replace already-installed perathos hook entries.")
@click.option("--recorder", is_flag=True,
              help="Also install the flight recorder: a hash-chained receipt for every tool call, "
                   "sealed by a signed checkpoint at the end of each turn.")
@click.option("--guard", is_flag=True,
              help="Recorder plus the destructive-command guard (implies --recorder).")
@click.option("--anchor", is_flag=True,
              help="Recorder plus RFC 3161 timestamps on every checkpoint (implies --recorder; needs network).")
def hooks_install(scope: str, force: bool, recorder: bool, guard: bool, anchor: bool):
    """Install the perathos hooks into Claude Code settings.

    Adds a Stop hook that runs 'perathos hooks stop-check' after every turn.
    It grounds the agent's final summary against this session's own tool
    outputs (extractive hallucination_detector) and recomputes any arithmetic
    (symbolic_solver) -- both local and deterministic, no LLM call, no
    network -- then writes a signed Proof Bundle receipt to
    .perathos/receipts/ in the session's working directory.

    With --recorder it also installs the flight recorder (PreToolUse,
    PostToolUse, Stop and SessionEnd hooks running 'perathos hooks record'),
    which writes .perathos/sessions/<session_id>.jsonl. Check a log with
    'perathos session verify'. Run 'perathos keygen' first so checkpoints
    are signed.

    Neither hook ever blocks the agent.
    """
    if scope == "project":
        settings_path = Path(".claude") / "settings.json"
    else:
        settings_path = Path.home() / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings = _load_settings(settings_path)
    hooks_block = settings.setdefault("hooks", {})

    recorder = recorder or guard or anchor
    _add_hook(hooks_block, "Stop", _STOP_CHECK_CMD, 30, force, settings_path)
    if recorder:
        for event in _RECORDER_EVENTS:
            flags = ""
            if guard and event == "PreToolUse":
                flags += " --guard"
            if anchor and event in ("Stop", "SessionEnd"):
                flags += " --anchor"
            _add_hook(hooks_block, event, _RECORD_CMD + flags, 20 if "--anchor" in flags else 10,
                      force, settings_path)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

    click.echo(f"Installed into {settings_path}.")
    click.echo("Every turn's summary will now be grounded against this session's tool")
    click.echo("outputs, and a signed Proof Bundle receipt written to .perathos/receipts/.")
    if recorder:
        click.echo("")
        click.echo("Flight recorder on: every tool call is recorded to .perathos/sessions/")
        click.echo("as a hash-chained receipt and sealed by a signed checkpoint each turn.")
        if guard:
            click.echo("Guard on: destructive commands are blocked unless a person has run")
            click.echo("'perathos precondition add' for that target.")
        if anchor:
            click.echo("Anchoring on: each checkpoint is timestamped by an outside service (freetsa.org).")
        try:
            load_signing_key()
        except (FileNotFoundError, ValueError):
            click.echo("[WARN] No signing key yet: run 'perathos keygen' or checkpoints will be unsigned.")
    click.echo("")
    click.echo("This grounds claims against what tools actually returned. It does not")
    click.echo("catch a well-grounded misrepresentation, and it never blocks the agent.")


def _local_verify_key() -> str | None:
    """The local public key (from 'perathos keygen'), or None if there is none."""
    try:
        vk = (keys_dir() / "verify.key").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return vk if len(vk) == 64 else None


@hooks.command(name="record")
@click.option("--guard", is_flag=True,
              help="Also block destructive commands that have no signed safety precondition.")
@click.option("--anchor", is_flag=True,
              help="Also send each signed checkpoint to an RFC 3161 timestamp service (needs perathos[anchor]).")
def hooks_record(guard: bool, anchor: bool):
    """Run as a Claude Code hook: append a flight-recorder receipt.

    Reads the hook payload from stdin. PreToolUse and PostToolUse append a
    chained receipt holding hashes (never content) of the tool's arguments
    and result. Stop and SessionEnd append a checkpoint signed with the local
    key from 'perathos keygen'.

    With --guard, a PreToolUse call matching a destructive-command rule is
    denied (via the hook's JSON permissionDecision) unless an unexpired
    precondition signed by the local key covers it; the decision is bound
    into the receipt. With --anchor, each signed checkpoint is timestamped
    by an outside TSA and the token saved under ~/.perathos/anchors/.

    Always exits 0. Without --guard nothing is printed to stdout, so the
    recorder can never block or alter the agent; problems go to stderr.
    """
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    event = payload.get("hook_event_name")

    decision = None
    if guard and event == "PreToolUse":
        try:
            from .guard import decide

            decision = decide(str(payload.get("tool_name") or ""), payload.get("tool_input"),
                              payload.get("cwd") or ".", trusted_key=_local_verify_key())
        except Exception as exc:  # noqa: BLE001 -- a broken guard must not brick the agent
            click.echo(f"perathos guard: {type(exc).__name__}: {exc}", err=True)

    receipt = None
    try:
        from .recorder import record_hook_event

        sk_hex = None
        if event in ("Stop", "SubagentStop", "SessionEnd"):
            try:
                sk_hex = load_signing_key()
            except (FileNotFoundError, ValueError):
                sk_hex = None
        receipt = record_hook_event(payload, signing_key_hex=sk_hex,
                                    guard_decision=decision.receipt_field() if decision else None)
    except Exception as exc:  # noqa: BLE001 -- a recorder must never break the session
        click.echo(f"perathos recorder: {type(exc).__name__}: {exc}", err=True)

    # The deny is emitted even if recording failed: the guard fails closed.
    if decision is not None and decision.decision == "deny":
        click.echo(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason,
        }}))

    if anchor and receipt and receipt.get("kind") == "checkpoint" and receipt.get("signature"):
        try:
            from .anchor import anchor_checkpoint, default_anchors_path

            anchor_checkpoint(receipt, default_anchors_path(receipt["session_id"]), timeout=8)
        except Exception as exc:  # noqa: BLE001 -- the timestamp service may be down; never fail the turn
            click.echo(f"perathos anchor: {type(exc).__name__}: {exc} (run 'perathos session anchor' later)", err=True)


@hooks.command(name="stop-check")
def hooks_stop_check():
    """Run as a Claude Code Stop hook (reads the hook's JSON payload from stdin).

    Grounds the turn's final assistant message against this session's own
    tool outputs (extractive hallucination_detector: flags a claimed amount,
    date, or quoted span with no support in any tool_result recorded this
    session) and recomputes any stated arithmetic (symbolic_solver). Both are
    local and deterministic -- no LLM call, no network access. Writes a
    signed Proof Bundle receipt to .perathos/receipts/ in the session's
    working directory (unsigned if no local key exists yet -- run
    'perathos keygen' to sign receipts).

    What this catches: a specific claim (a number, a quoted status, a named
    file) with no support in this session's own tool outputs -- e.g. "all
    tests pass" with no passing test output anywhere in the transcript.

    What this does NOT catch: a claim that IS grounded in a tool output but
    still misrepresents the larger picture, or anything requiring judgment
    beyond exact/lenient text and arithmetic matching.

    Always exits 0 -- this hook only observes and records; it never blocks
    the agent from stopping. A finding is surfaced to Claude via
    'additionalContext' on the JSON written to stdout, per the Stop-hook
    protocol, so the next turn sees it as context, not as an error.
    """
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        # Malformed input from the harness -- never fail the turn over this.
        click.echo("{}")
        return
    if not isinstance(payload, dict):
        click.echo("{}")
        return

    from .hooks import check_stop_hook

    result = check_stop_hook(payload)
    cwd = payload.get("cwd") or "."
    receipts_dir = Path(cwd) / ".perathos" / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)

    bundle = result["bundle"]
    try:
        sk_hex = load_signing_key()
        bundle = sign(bundle, sk_hex)
    except FileNotFoundError:
        pass  # An unsigned receipt is still useful; signing is opt-in (perathos keygen).

    session_id = str(payload.get("session_id") or "unknown")[:8]
    stamp = str(bundle.get("issued_at", "")).replace(":", "").replace("+00:00", "Z") or "unknown"
    receipt_path = receipts_dir / f"{stamp}-{session_id}.json"
    receipt_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")

    output: dict = {}
    if result["failing_records"]:
        details = "; ".join(r.get("detail", "") for r in result["failing_records"])
        output = {
            "hookSpecificOutput": {
                "hookEventName": "Stop",
                "additionalContext": (
                    f"perathos: this turn's summary has claim(s) not grounded in this "
                    f"session's own tool outputs -- {details}. Receipt: {receipt_path}"
                ),
            }
        }
    click.echo(json.dumps(output))


@cli.group()
def session():
    """Inspect and verify flight-recorder session logs."""


def _resolve_session_log(target: str) -> Path:
    p = Path(target)
    if p.exists():
        return p
    sessions_dir = Path(".perathos") / "sessions"
    candidate = sessions_dir / f"{target}.jsonl"
    if candidate.exists():
        return candidate
    matches = sorted(sessions_dir.glob(f"{target}*.jsonl")) if sessions_dir.exists() else []
    if len(matches) == 1:
        return matches[0]
    click.echo(f"[ERROR] Session log not found: {target}", err=True)
    click.echo("List logs with: perathos session list", err=True)
    sys.exit(2)


@session.command(name="list")
def session_list():
    """List session logs in ./.perathos/sessions/."""
    d = Path(".perathos") / "sessions"
    logs = sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True) if d.exists() else []
    if not logs:
        click.echo("No session logs in ./.perathos/sessions/. Install with: perathos hooks install --recorder")
        return
    for p in logs:
        n = sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
        click.echo(f"{p.stem}  {n} receipts  {p}")


@session.command(name="verify")
@click.argument("target")
@click.option("--verify-key", "expected_verify_key", default=None, metavar="HEX",
              help="Pin the expected signer's 64-char hex public key.")
@click.option("--trust-jwks", "trust_jwks", type=click.Path(exists=True), default=None, metavar="PATH",
              help="Accept only checkpoints signed by a key in this JWKS file.")
@click.option("--allow-unsigned", is_flag=True,
              help="Accept unsigned checkpoints (hash-chain consistency only).")
@click.option("--anchors", "anchors_file", type=click.Path(), default=None, metavar="PATH",
              help="Anchors file to check (default: ~/.perathos/anchors/<session_id>.jsonl if present).")
@click.option("--require-anchor", is_flag=True,
              help="Fail unless the last checkpoint carries a valid independent timestamp.")
@click.option("--tsa-root", "tsa_roots", multiple=True, type=click.Path(exists=True), metavar="PEM",
              help="Extra trusted TSA root certificate(s), besides the pinned FreeTSA root.")
@click.option("--json", "as_json", is_flag=True, help="Print the full report as JSON.")
def session_verify(target: str, expected_verify_key: str, trust_jwks: str, allow_unsigned: bool,
                   anchors_file: str, require_anchor: bool, tsa_roots: tuple, as_json: bool):
    """Verify a session log: chain, sequence, signatures and truncation.

    TARGET is a path to a .jsonl log or a session id (prefix) under
    ./.perathos/sessions/. Exit 0 = valid, 1 = invalid, 2 = usage error.

    Detects any edited, deleted, inserted or reordered receipt, a forged or
    re-signed checkpoint, and truncation before the last witnessed
    checkpoint. Receipts after the last checkpoint are reported as unsealed.
    """
    from .recorder import verify_session

    trust_store = None
    if trust_jwks:
        from .keytrust import TrustStore
        try:
            trust_store = TrustStore.from_jwks(json.loads(Path(trust_jwks).read_text(encoding="utf-8")))
        except ValueError as exc:
            click.echo(f"[ERROR] Invalid JWKS file {trust_jwks}: {exc}", err=True)
            sys.exit(2)

    log = _resolve_session_log(target)
    anchors_path = Path(anchors_file) if anchors_file else None
    if anchors_path is None:
        from .recorder import safe_session_id
        default = Path.home() / ".perathos" / "anchors" / f"{safe_session_id(log.stem)}.jsonl"
        anchors_path = default if default.exists() else None
    roots = None
    if anchors_path is not None or require_anchor:
        try:
            from .anchor import load_roots
            roots = load_roots(list(tsa_roots))
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Cannot check timestamps: {exc}", err=True)
            sys.exit(2)
    report = verify_session(log, expected_verify_key=expected_verify_key,
                            trust_store=trust_store, require_signed=not allow_unsigned,
                            anchors_path=anchors_path, tsa_roots=roots, require_anchor=require_anchor)
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        status = "VALID" if report.valid else "INVALID"
        click.echo(f"{status}  {log}")
        click.echo(f"  session       {report.session_id}")
        click.echo(f"  receipts      {report.receipts} ({report.tool_calls} tool calls, {report.checkpoints} checkpoints)")
        click.echo(f"  sealed        through seq {report.sealed_through} by {report.signed_checkpoints} signed checkpoint(s)")
        if report.signers:
            click.echo(f"  signer        {', '.join(report.signers)}")
        if report.models:
            click.echo(f"  model         {', '.join(report.models)} (self-reported)")
        if report.first_ts:
            click.echo(f"  time          {report.first_ts} to {report.last_ts} (local clock)")
        if report.anchors:
            click.echo(f"  timestamped   through seq {report.anchored_through} at {report.anchored_time} "
                       f"(independent, {report.anchors} token(s))")
        if report.blocked:
            click.echo(f"  blocked       {report.blocked} destructive call(s) stopped by the guard")
        for e in report.errors:
            click.echo(f"[ERROR] {e}", err=True)
        for w in report.warnings:
            click.echo(f"[WARN]  {w}")
    sys.exit(0 if report.valid else 1)


@session.command(name="show")
@click.argument("target")
def session_show(target: str):
    """Print a session log as a readable timeline."""
    log = _resolve_session_log(target)
    for line in log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            click.echo("  ?? unparseable line")
            continue
        kind = r.get("kind")
        ts = str(r.get("ts", ""))[11:23]
        seq = str(r.get("seq")).rjust(5)
        if kind == "pre":
            click.echo(f"{seq}  {ts}  call    {r.get('tool')}  args {str(r.get('args_hash'))[:12]}")
        elif kind == "post":
            click.echo(f"{seq}  {ts}  result  {r.get('tool')}  {r.get('status')}  out {str(r.get('result_hash'))[:12]}")
        elif kind == "checkpoint":
            signed = "signed" if r.get("signature") else "UNSIGNED"
            click.echo(f"{seq}  {ts}  SEAL    {r.get('event')}  {signed}  {str(r.get('receipt_hash'))[:12]}")
        else:
            click.echo(f"{seq}  {ts}  {kind}")


@session.command(name="anchor")
@click.argument("target")
@click.option("--tsa-url", default=None, metavar="URL", help="RFC 3161 service (default: https://freetsa.org/tsr).")
@click.option("--tsa-root", "tsa_roots", multiple=True, type=click.Path(exists=True), metavar="PEM",
              help="Trusted root for a non-default TSA.")
@click.option("--anchors", "anchors_file", type=click.Path(), default=None, metavar="PATH",
              help="Where to store anchors (default: ~/.perathos/anchors/<session_id>.jsonl).")
def session_anchor(target: str, tsa_url: str, tsa_roots: tuple, anchors_file: str):
    """Timestamp every not-yet-anchored checkpoint of a session with an outside TSA.

    The TSA signs "this checkpoint hash existed at time T". Keep a copy of the
    anchors file somewhere the agent cannot reach: then cutting the end off
    the log is detectable by 'perathos session verify --anchors <copy>'.
    """
    from .anchor import DEFAULT_TSA_URL, anchor_session, load_roots

    log = _resolve_session_log(target)
    try:
        new = anchor_session(log, Path(anchors_file) if anchors_file else None,
                             url=tsa_url or DEFAULT_TSA_URL, roots=load_roots(list(tsa_roots)))
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[ERROR] Timestamping failed: {type(exc).__name__}: {exc}", err=True)
        sys.exit(1)
    if not new:
        click.echo("Nothing to anchor: every checkpoint already has a timestamp (or there are none).")
        return
    for a in new:
        click.echo(f"anchored  seq {a['seq']}  {a['gen_time']}  {a['tsa']}")


@cli.group()
def precondition():
    """Signed safety checks that let the guard allow a destructive command."""


@precondition.command(name="add")
@click.option("--scope", required=True,
              help="Text that must appear in the destructive command (e.g. a database or volume name), or '*'.")
@click.option("--check", "check_cmd", default=None, metavar="COMMAND",
              help="Command proving the safeguard holds, e.g. that a backup restores. Must exit 0.")
@click.option("--manual", "manual_reason", default=None, metavar="REASON",
              help="Instead of a command: your own signed attestation and the reason for it.")
@click.option("--ttl", "ttl_minutes", default=30, show_default=True, type=click.IntRange(1, 24 * 60),
              help="Minutes until the precondition expires.")
def precondition_add(scope: str, check_cmd: str, manual_reason: str, ttl_minutes: int):
    """Run a safety check and, if it passes, sign a precondition for SCOPE.

    Run this yourself, outside the agent session. The guard refuses agent
    attempts to call it.

    Example:
        perathos precondition add --scope prod-db --check "pg_restore --list backups/prod.dump"
    """
    from .guard import create_precondition

    try:
        sk_hex = load_signing_key()
    except (FileNotFoundError, ValueError):
        click.echo("[ERROR] No signing key. Run: perathos keygen", err=True)
        sys.exit(1)
    try:
        pc, result = create_precondition(Path("."), scope=scope, signing_key_hex=sk_hex, check=check_cmd,
                                         manual_reason=manual_reason, ttl_minutes=ttl_minutes)
    except ValueError as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(2)
    if pc is None:
        click.echo(f"[ERROR] Check failed (exit {result['exit_code']}); no precondition was created.", err=True)
        tail = result["output"].strip().splitlines()[-5:]
        for line in tail:
            click.echo(f"  {line}", err=True)
        sys.exit(1)
    click.echo(f"precondition  {pc['id']}")
    click.echo(f"scope         {pc['scope']}")
    if pc["check"]:
        click.echo(f"check         {pc['check']}  (exit 0)")
    else:
        click.echo(f"manual        {pc['manual_reason']}")
    click.echo(f"expires       {pc['expires']}")


@precondition.command(name="list")
def precondition_list():
    """List preconditions in ./.perathos/preconditions/ and whether each is usable now."""
    from .guard import check_precondition, preconditions_dir

    d = preconditions_dir(".")
    files = sorted(d.glob("*.json")) if d.exists() else []
    if not files:
        click.echo("No preconditions.")
        return
    vk = _local_verify_key()
    for f in files:
        try:
            pc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            click.echo(f"?  {f.name}  unreadable")
            continue
        problem = check_precondition(pc, trusted_key=vk) if vk else "no local key"
        status = "VALID" if problem is None else problem
        click.echo(f"{pc.get('id', f.stem)[:8]}  scope={pc.get('scope')!r}  expires={pc.get('expires')}  {status}")


def main():
    cli()
