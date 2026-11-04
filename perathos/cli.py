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


def _is_perathos_stop_hook(entry) -> bool:
    return isinstance(entry, dict) and str(entry.get("command", "")).startswith("perathos hooks stop-check")


@hooks.command(name="install")
@click.option("--scope", type=click.Choice(["project", "user"]), default="project",
              help="Install into .claude/settings.json (project, default) or ~/.claude/settings.json (user).")
@click.option("--force", is_flag=True, help="Replace an already-installed perathos Stop hook entry.")
def hooks_install(scope: str, force: bool):
    """Install the perathos Stop hook into Claude Code settings.

    Adds a Stop hook that runs 'perathos hooks stop-check' after every turn.
    It grounds the agent's final summary against this session's own tool
    outputs (extractive hallucination_detector) and recomputes any arithmetic
    (symbolic_solver) -- both local and deterministic, no LLM call, no
    network -- then writes a signed Proof Bundle receipt to
    .perathos/receipts/ in the session's working directory.

    It never blocks the agent. A finding is surfaced to Claude as context on
    the next turn, not as a failure. See 'perathos hooks stop-check --help'
    for exactly what it does and does not catch.
    """
    settings_path = (Path(".claude") / "settings.json") if scope == "project" else (Path.home() / ".claude" / "settings.json")
    settings_path.parent.mkdir(parents=True, exist_ok=True)

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

    hooks_block = settings.setdefault("hooks", {})
    stop_hooks = hooks_block.setdefault("Stop", [])
    existing = [h for h in stop_hooks if _is_perathos_stop_hook(h)]
    if existing and not force:
        click.echo(f"[ERROR] A perathos Stop hook is already installed in {settings_path}.", err=True)
        click.echo("Use --force to reinstall.", err=True)
        sys.exit(1)
    if existing:
        hooks_block["Stop"] = [h for h in stop_hooks if not _is_perathos_stop_hook(h)]
        stop_hooks = hooks_block["Stop"]

    stop_hooks.append({"type": "command", "command": "perathos hooks stop-check", "timeout": 30})
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")

    click.echo(f"Installed into {settings_path}.")
    click.echo("Every turn's summary will now be grounded against this session's tool")
    click.echo("outputs, and a signed Proof Bundle receipt written to .perathos/receipts/.")
    click.echo("")
    click.echo("This grounds claims against what tools actually returned. It does not")
    click.echo("catch a well-grounded misrepresentation, and it never blocks the agent.")


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


def main():
    cli()
