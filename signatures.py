from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


RSA_KEY_SIZE = 2048


def generate_signing_key_pair():
    """Generate an RSA private key and its matching public key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    return private_key, public_key


def sign_message(message: bytes, private_key) -> bytes:
    """Create an RSA-PSS digital signature for a message."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(
    message: bytes,
    signature: bytes,
    public_key
) -> bool:
    """Verify an RSA-PSS digital signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False


def serialize_public_key(public_key) -> bytes:
    """Serialize the public key for transmission or storage."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )