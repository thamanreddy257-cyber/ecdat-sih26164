"""Merchant key handling for settlement files."""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def new_merchant_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_settlement(key, payload: bytes) -> bytes:
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
