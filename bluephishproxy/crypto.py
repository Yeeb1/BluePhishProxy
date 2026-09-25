"""Authenticated encryption using only Python stdlib.

Uses PBKDF2-derived keys with a XOR stream cipher and HMAC-SHA256
for integrity. No external dependencies required.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os


def _derive_key(master_key: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", master_key.encode(), salt, 100_000)


def encrypt(plaintext: str, master_key: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(master_key, salt)
    pt_bytes = plaintext.encode("utf-8")
    keystream = b""
    for i in range((len(pt_bytes) // 32) + 1):
        keystream += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
    ct = bytes(a ^ b for a, b in zip(pt_bytes, keystream))
    mac = hmac.new(key, ct, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(salt + mac + ct).decode("ascii")


def decrypt(token: str, master_key: str) -> str:
    raw = base64.urlsafe_b64decode(token)
    if len(raw) < 48:
        raise ValueError("invalid ciphertext")
    salt, mac, ct = raw[:16], raw[16:48], raw[48:]
    key = _derive_key(master_key, salt)
    expected_mac = hmac.new(key, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("tampered ciphertext")
    keystream = b""
    for i in range((len(ct) // 32) + 1):
        keystream += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
    pt = bytes(a ^ b for a, b in zip(ct, keystream))
    return pt.decode("utf-8")
