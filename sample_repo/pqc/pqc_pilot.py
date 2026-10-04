"""Pilot: post-quantum key establishment and signing via liboqs-python."""
import oqs


def pilot():
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    signer = oqs.Signature("ML-DSA-65")
    return kem, signer
