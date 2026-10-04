"""Session and token helpers (legacy)."""
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def password_fingerprint(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()


def session_id(user: str) -> str:
    return hashlib.sha1(user.encode() + os.urandom(8)).hexdigest()


def encrypt_token(token: bytes, key_128: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key_128), modes.ECB()).encryptor()
    return encryptor.update(token.ljust(32, b"\0")) + encryptor.finalize()
