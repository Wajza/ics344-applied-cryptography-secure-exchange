import os

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_KEY_SIZE = 32       # 32 bytes = 256 bits
AES_BLOCK_SIZE = 128    # AES block size in bits
IV_SIZE = 16            # CBC IV size
NONCE_SIZE = 16         # CTR nonce size
HMAC_KEY_SIZE = 32      # 32 bytes = 256 bits


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(AES_KEY_SIZE)


def encrypt_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-CBC with PKCS7 padding."""
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
    """Decrypt AES-256-CBC ciphertext and remove PKCS7 padding."""
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


def encrypt_ctr(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-CTR."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes.")

    nonce = os.urandom(NONCE_SIZE)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, nonce


def decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-256-CTR ciphertext."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError("CTR nonce must be exactly 16 bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("CTR nonce must be exactly 16 bytes.")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def generate_hmac_key() -> bytes:
    """Generate a random 256-bit HMAC key."""
    return os.urandom(HMAC_KEY_SIZE)


def create_hmac(data: bytes, key: bytes) -> bytes:
    """Create an HMAC-SHA-256 tag."""
    if len(key) != HMAC_KEY_SIZE:
        raise ValueError("HMAC key must be exactly 32 bytes.")

    hmac_calculator = hmac.HMAC(key, hashes.SHA256())
    hmac_calculator.update(data)

    return hmac_calculator.finalize()


def verify_hmac(data: bytes, tag: bytes, key: bytes) -> bool:
    """Verify an HMAC-SHA-256 tag."""
    if len(key) != HMAC_KEY_SIZE:
        raise ValueError("HMAC key must be exactly 32 bytes.")

    hmac_calculator = hmac.HMAC(key, hashes.SHA256())
    hmac_calculator.update(data)

    try:
        hmac_calculator.verify(tag)
        return True
    except Exception:
        return False