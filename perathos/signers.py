"""Where signatures come from: a local key, or a key that never touches this machine.

A *signer spec* is a short string naming the key:

* ``local`` (default): ``~/.perathos/keys/signing.key`` from ``perathos keygen``.
* ``command:<command line>``: any program that follows a two-verb protocol:
  ``<command> pubkey`` prints the Ed25519 public key as 64 hex characters, and
  ``<command> sign`` reads a hex message on stdin and prints the 64-byte
  Ed25519 signature as hex. Wrap a YubiKey, an HSM, an SSH agent, a password
  manager or a remote signing service this way.
* ``vault:<mount>/<key>``: HashiCorp Vault transit engine, Ed25519 key.
  Needs ``VAULT_ADDR`` and ``VAULT_TOKEN`` (and ``VAULT_NAMESPACE`` if used).
* ``gcpkms:<cryptoKeyVersion resource name>``: Google Cloud KMS key of type
  ``EC_SIGN_ED25519``. Needs ``pip install google-cloud-kms`` and application
  default credentials.

Configure with ``perathos config set signer <spec>`` or the ``PERATHOS_SIGNER``
environment variable. Every signer verifies its own signature against its
public key before returning it, so a misconfigured remote key fails loudly
instead of producing a log nobody can verify.

AWS KMS is not listed: wrap it with ``command:`` if your account offers an
Ed25519 key type.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import urllib.request
from pathlib import Path
from typing import Callable

from .keytrust import KmsSigner, LocalSigner, Signer

_TIMEOUT = 10


class SignerError(RuntimeError):
    """The configured signer could not be loaded or did not sign correctly."""


def _checked(signer_name: str, public_key: bytes, sign_fn: Callable[[bytes], bytes]) -> Signer:
    """Wrap a remote sign function so every signature is verified before use."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(public_key) != 32:
        raise SignerError(f"{signer_name}: public key must be 32 bytes, got {len(public_key)}")
    pub = Ed25519PublicKey.from_public_bytes(public_key)

    def sign(payload: bytes) -> bytes:
        sig = sign_fn(payload)
        try:
            pub.verify(sig, payload)
        except InvalidSignature:
            raise SignerError(f"{signer_name}: returned a signature that does not verify against its public key") from None
        return sig

    return KmsSigner(key_id=signer_name, public_key=public_key, sign_fn=sign)


# --------------------------------------------------------------------------- #
# command:
# --------------------------------------------------------------------------- #

def command_signer(command: str) -> Signer:
    if os.name == "nt":
        # Non-POSIX splitting keeps backslashes in Windows paths but also keeps
        # the quote characters around each token; strip them.
        argv = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t
                for t in shlex.split(command, posix=False)]
    else:
        argv = shlex.split(command)
    if not argv:
        raise SignerError("command signer: empty command")

    def run(verb: str, stdin: str = "") -> str:
        try:
            proc = subprocess.run([*argv, verb], input=stdin, capture_output=True, text=True, timeout=_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SignerError(f"command signer: {exc}") from exc
        if proc.returncode != 0:
            raise SignerError(f"command signer: '{verb}' exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        return proc.stdout.strip()

    try:
        pub = bytes.fromhex(run("pubkey"))
    except ValueError as exc:
        raise SignerError("command signer: 'pubkey' must print 64 hex characters") from exc

    def sign(payload: bytes) -> bytes:
        try:
            return bytes.fromhex(run("sign", payload.hex()))
        except ValueError as exc:
            raise SignerError("command signer: 'sign' must print the signature as hex") from exc

    return _checked(f"command:{argv[0]}", pub, sign)


# --------------------------------------------------------------------------- #
# vault:
# --------------------------------------------------------------------------- #

def vault_signer(path: str, *, addr: str | None = None, token: str | None = None) -> Signer:
    """HashiCorp Vault transit engine: `vault:<mount>/<key>` (mount defaults to transit)."""
    addr = (addr or os.environ.get("VAULT_ADDR") or "").rstrip("/")
    token = token or os.environ.get("VAULT_TOKEN") or ""
    if not addr or not token:
        raise SignerError("vault signer: set VAULT_ADDR and VAULT_TOKEN")
    mount, _, key = path.rpartition("/")
    mount = mount or "transit"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    if os.environ.get("VAULT_NAMESPACE"):
        headers["X-Vault-Namespace"] = os.environ["VAULT_NAMESPACE"]

    def call(method: str, url: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(url, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 - operator-configured Vault
                return json.load(resp)
        except Exception as exc:  # noqa: BLE001
            raise SignerError(f"vault signer: {method} {url}: {exc}") from exc

    info = call("GET", f"{addr}/v1/{mount}/keys/{key}")["data"]
    if info.get("type") != "ed25519":
        raise SignerError(f"vault signer: key {key} is {info.get('type')}, need ed25519")
    latest = str(info.get("latest_version"))
    pub = base64.b64decode(info["keys"][latest]["public_key"])

    def sign(payload: bytes) -> bytes:
        out = call("POST", f"{addr}/v1/{mount}/sign/{key}", {"input": base64.b64encode(payload).decode()})
        sig = out["data"]["signature"]  # "vault:v<N>:<base64>"
        return base64.b64decode(sig.split(":")[-1])

    return _checked(f"vault:{mount}/{key}", pub, sign)


# --------------------------------------------------------------------------- #
# gcpkms:
# --------------------------------------------------------------------------- #

def gcpkms_signer(name: str, *, client=None) -> Signer:
    """Google Cloud KMS EC_SIGN_ED25519 key version (PureEdDSA over the raw message)."""
    if client is None:
        try:
            from google.cloud import kms  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SignerError("gcpkms signer: pip install google-cloud-kms") from exc
        client = kms.KeyManagementServiceClient()
    from cryptography.hazmat.primitives import serialization

    try:
        pem = client.get_public_key(request={"name": name}).pem
        pub = serialization.load_pem_public_key(pem.encode()).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception as exc:  # noqa: BLE001
        raise SignerError(f"gcpkms signer: cannot read public key: {exc}") from exc

    def sign(payload: bytes) -> bytes:
        try:
            return client.asymmetric_sign(request={"name": name, "data": payload}).signature
        except Exception as exc:  # noqa: BLE001
            raise SignerError(f"gcpkms signer: {exc}") from exc

    return _checked(f"gcpkms:{name.rsplit('/cryptoKeys/', 1)[-1]}", pub, sign)


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #

def local_signer(home: Path | None = None) -> Signer:
    path = (home or Path.home()) / ".perathos" / "keys" / "signing.key"
    try:
        sk = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SignerError("no local signing key (run: perathos keygen)") from exc
    try:
        return LocalSigner.from_hex(sk)
    except ValueError as exc:
        raise SignerError(f"local signing key is malformed: {exc}") from exc


def signer_from_spec(spec: str) -> Signer:
    spec = (spec or "local").strip()
    kind, _, rest = spec.partition(":")
    if kind == "local":
        return local_signer()
    if kind == "command":
        return command_signer(rest)
    if kind == "vault":
        return vault_signer(rest)
    if kind == "gcpkms":
        return gcpkms_signer(rest)
    raise SignerError(f"unknown signer spec {spec!r} (use local, command:, vault: or gcpkms:)")


def configured_spec() -> str:
    """The recorder's signer: $PERATHOS_SIGNER, else `perathos config` signer, else local."""
    from .approvers import get_config
    return os.environ.get("PERATHOS_SIGNER") or get_config().get("signer") or "local"


def load_signer(spec: str | None = None) -> Signer:
    return signer_from_spec(spec or configured_spec())
