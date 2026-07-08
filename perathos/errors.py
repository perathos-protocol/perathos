"""Human-readable explanations for perathos verification error codes.

Shared by the CLI (`perathos verify`) and the MCP server
(`perathos_verify_bundle`) so both surfaces give the exact same actionable
explanation for a given error code, not two copies that can drift.
"""

_ERROR_EXPLANATIONS = {
    "ERR_MISSING_TRACE": "Bundle is missing execution metadata (_trace field). The bundle file may be corrupted or truncated. Next step: Check the bundle file with 'python -m json.tool <bundle_path>' to validate JSON syntax.",
    "ERR_TRACE_HASH_MISMATCH": "Execution metadata was tampered with. The hash chain is broken — the _trace field doesn't match trace_hash. Next step: Do not trust this bundle. Verify the source and obtain the original bundle from the provider.",
    "ERR_INTEGRITY_HASH_MISMATCH": "Bundle fields (ai_id, input_hash, output_hash, issued_at, or trace_hash) were tampered with. The bundle has been modified since creation. Next step: Do not trust this bundle. This is a critical tamper detection.",
    "ERR_BUNDLE_ID_MISMATCH": "Bundle ID was manually changed or corrupted. The bundle_id field doesn't match the integrity_hash. Next step: Do not trust this bundle. Verify the source and obtain the original bundle from the provider.",
    "ERR_BAD_SIGNATURE": "Cryptographic signature is invalid. The bundle or signature was modified after signing, or the signing key is incorrect. Next step: Verify the provider's public key and ask them to confirm the bundle hasn't been modified.",
    "ERR_MISSING_FIELD": "Bundle is missing a required field. The bundle structure is invalid or corrupted. Next step: Check the bundle file with 'python -m json.tool <bundle_path>' to see which fields are present.",
    "ERR_NO_SIGNING_KEY": "Signing key not found. To generate a keypair, run: perathos keygen. Then sign your bundle with: perathos prove '<output_text>' --sign",
    "ERR_UNEXPECTED_SIGNER": "The bundle's signature is valid but was made by a different key than the one you pinned with --verify-key. Next step: Confirm the expected signer's public key; this bundle was signed by someone else.",
    "ERR_UNTRUSTED_SIGNER": "The bundle's signature is valid but the signing key is not in the trust set you provided (--trust-jwks). Next step: Obtain the issuer's published JWKS and confirm the key is one you trust.",
    "ERR_VERDICT_MISMATCH": "The bundle's top-level verdict does not match its bound aggregate verdict — the convenience field was tampered with. Next step: Do not trust this bundle.",
    "ERR_ANSWER_MISMATCH": "The bundle's stored answer text does not hash to its output_hash — the answer was altered after creation. Next step: Do not trust this bundle.",
    "ERR_MALFORMED_BUNDLE": "The bundle structure is malformed and could not be verified (e.g. a corrupted or hostile _trace). Next step: Obtain the original bundle from the provider; do not trust this one.",
    "ERR_UNSUPPORTED_ALGORITHM": "The bundle's signature declares an algorithm other than ed25519, which is the only supported scheme. Next step: Do not trust this bundle; its signature was not validated.",
    "ERR_INPUT_FILE_NOT_FOUND": "Input file not found. Check that the file exists and the path is correct. Example: perathos prove 'output' --input-file prompt.txt",
    "ERR_INPUT_FILE_READ": "Failed to read input file. Check that the file is readable and not corrupted. Example: perathos prove 'output' --input-file prompt.txt",
}


def explain_error(error_code: str) -> str:
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
        explain_error("ERR_TRACE_HASH_MISMATCH")
        → "Execution metadata was tampered with. The hash chain is broken — ..."

        explain_error("ERR_MISSING_FIELD:output_hash")
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
