"""Envelope cifrado com libsodium via PyNaCl (Argon2id + XChaCha20-Poly1305)."""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any

try:
    from nacl import bindings, pwhash
    from nacl.exceptions import CryptoError
except ImportError as exc:  # pragma: no cover - checked at runtime in packaged app
    raise RuntimeError("Instale PyNaCl para abrir o cofre criptografado.") from exc

FORMAT = "cofre-universal-encrypted-v1"
AAD = b"cofre-universal/encrypted-v1"
SALT_BYTES = pwhash.argon2id.SALTBYTES
KEY_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
OPS_LIMIT = pwhash.argon2id.OPSLIMIT_INTERACTIVE
MEM_LIMIT = pwhash.argon2id.MEMLIMIT_INTERACTIVE


class InvalidMasterPassword(ValueError):
    """Senha mestra incorreta ou envelope danificado."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 12:
        raise ValueError("A senha mestra deve ter pelo menos 12 caracteres.")
    if len(salt) != SALT_BYTES:
        raise ValueError("Salt do cofre inválido.")
    return pwhash.argon2id.kdf(
        KEY_BYTES, password.encode("utf-8"), salt,
        opslimit=OPS_LIMIT, memlimit=MEM_LIMIT,
    )


def encrypt_payload(payload: dict[str, Any], key: bytes, salt: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, AAD, nonce, key)
    envelope = {
        "format": FORMAT,
        "kdf": {"name": "argon2id", "opslimit": OPS_LIMIT, "memlimit": MEM_LIMIT, "salt": _b64(salt)},
        "aead": {"name": "xchacha20-poly1305", "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)},
    }
    return json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def decrypt_payload(envelope_bytes: bytes, password: str | None = None, key: bytes | None = None) -> tuple[dict[str, Any], bytes, bytes]:
    """Abre envelope e devolve (payload, chave, salt); segredos nunca são logados."""
    try:
        envelope = json.loads(envelope_bytes)
        if envelope["format"] != FORMAT or envelope["kdf"]["name"] != "argon2id" or envelope["aead"]["name"] != "xchacha20-poly1305":
            raise ValueError("Formato não suportado.")
        if envelope["kdf"].get("opslimit") != OPS_LIMIT or envelope["kdf"].get("memlimit") != MEM_LIMIT:
            raise ValueError("Parâmetros de derivação não reconhecidos.")
        salt = _unb64(envelope["kdf"]["salt"])
        nonce = _unb64(envelope["aead"]["nonce"])
        ciphertext = _unb64(envelope["aead"]["ciphertext"])
        key = key or derive_key(password or "", salt)
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, AAD, nonce, key)
        payload = json.loads(plaintext)
        if not isinstance(payload, dict) or payload.get("version") != 1 or not isinstance(payload.get("credentials"), list):
            raise ValueError("Conteúdo do cofre inválido.")
        return payload, key, salt
    except (CryptoError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidMasterPassword("Senha mestra incorreta ou arquivo do cofre danificado.") from exc


def create_envelope(password: str, payload: dict[str, Any] | None = None) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive_key(password, salt)
    data = payload or {"version": 1, "credentials": []}
    return encrypt_payload(data, key, salt), key
