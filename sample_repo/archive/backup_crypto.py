"""Backup encryption - the GOOD example: AES-256-GCM + SHA-256."""
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import aead


def encrypt_backup(data: bytes) -> tuple[bytes, bytes, str]:
    cipher = aead.AESGCM(aead.AESGCM.generate_key(bit_length=256))
    nonce = os.urandom(12)
    checksum = hashlib.sha256(data).hexdigest()
    return nonce, cipher.encrypt(nonce, data, None), checksum
