from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh


DH_KEY_SIZE = 2048
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32


def generate_dh_parameters():
    """Generate 2048-bit finite-field Diffie-Hellman parameters."""
    return dh.generate_parameters(
        generator=2,
        key_size=DH_KEY_SIZE
    )


def generate_dh_key_pair(parameters):
    """Generate a private and public Diffie-Hellman key pair."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """Derive the shared Diffie-Hellman secret."""
    return private_key.exchange(peer_public_key)


def hash_key_material(data: bytes, label: bytes) -> bytes:
    """Derive a 256-bit key using SHA-256 and a purpose label."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(label)
    digest.update(data)

    return digest.finalize()


def derive_session_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """
    Derive separate AES and HMAC keys from the shared secret.

    Returns:
        AES key, HMAC key
    """
    aes_key = hash_key_material(
        shared_secret,
        b"ICS344 AES-256 encryption key"
    )

    hmac_key = hash_key_material(
        shared_secret,
        b"ICS344 HMAC-SHA-256 authentication key"
    )

    return aes_key, hmac_key