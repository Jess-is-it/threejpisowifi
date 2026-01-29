from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64url_decode_nopad(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@dataclass(frozen=True)
class TokenBox:
    key_b64url: str

    def _aesgcm(self) -> AESGCM:
        key = _b64url_decode_nopad(self.key_b64url)
        if len(key) != 32:
            raise ValueError("DEVICE_TOKEN_ENC_KEY must be 32 bytes (urlsafe base64 without padding is OK)")
        return AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        aesgcm = self._aesgcm()
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), b"centralwifi:device_token")
        return _b64url_encode_nopad(nonce + ct)

    def decrypt(self, token_enc: str) -> str:
        aesgcm = self._aesgcm()
        raw = _b64url_decode_nopad(token_enc)
        nonce, ct = raw[:12], raw[12:]
        pt = aesgcm.decrypt(nonce, ct, b"centralwifi:device_token")
        return pt.decode()

