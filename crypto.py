from __future__ import annotations

import base64
import hashlib
import os


def _derive_key(raw_key: str | None) -> bytes:
    if not raw_key:
        raise ValueError("DEVICE_CREDENTIALS_ENCRYPTION_KEY is required.")
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def encrypt_text(plaintext: str, raw_key: str | None) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ModuleNotFoundError as exc:
        raise RuntimeError("cryptography is required for credential encryption.") from exc

    key = _derive_key(raw_key)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_text(ciphertext: str, raw_key: str | None) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ModuleNotFoundError as exc:
        raise RuntimeError("cryptography is required for credential encryption.") from exc

    key = _derive_key(raw_key)
    payload = base64.b64decode(ciphertext.encode("ascii"))
    nonce, data = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, None).decode("utf-8")


def redact_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 6:
        return "***"
    return f"{value[:2]}***{value[-2:]}"
