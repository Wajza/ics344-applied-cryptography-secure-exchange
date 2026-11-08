import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_KEY_SIZE = 32       # 32 bytes = 256 bits
AES_BLOCK_SIZE = 128    # AES block size in bits
IV_SIZE = 16            # 16 bytes = 128 bits


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(AES_KEY_SIZE)


def encrypt_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-CBC.

    Returns:
        ciphertext, iv
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes.")

    iv = os.urandom(IV_SIZE)

    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext, iv


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-256-CBC ciphertext and remove PKCS7 padding.

    Returns:
        Original plaintext
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes.")

    if len(iv) != IV_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes.")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext