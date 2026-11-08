import argparse
from pathlib import Path

from crypto_utils import (
    encrypt_cbc,
    decrypt_cbc,
    encrypt_ctr,
    decrypt_ctr,
    create_hmac,
    verify_hmac,
)

from key_exchange import (
    generate_dh_parameters,
    generate_dh_key_pair,
    derive_shared_secret,
    derive_session_keys,
)

from signatures import (
    generate_signing_key_pair,
    sign_message,
    verify_signature,
)


def alice_prepare_message(
    message: bytes,
    aes_key: bytes,
    hmac_key: bytes,
    signing_private_key,
    mode: str,
) -> dict:
    """Alice encrypts, authenticates, and signs the message."""

    if mode.upper() == "CBC":
        ciphertext, iv_or_nonce = encrypt_cbc(message, aes_key)
    elif mode.upper() == "CTR":
        ciphertext, iv_or_nonce = encrypt_ctr(message, aes_key)
    else:
        raise ValueError("Mode must be either CBC or CTR.")

    protected_data = iv_or_nonce + ciphertext
    hmac_tag = create_hmac(protected_data, hmac_key)
    signature = sign_message(message, signing_private_key)

    return {
        "ciphertext": ciphertext,
        "iv_or_nonce": iv_or_nonce,
        "hmac_tag": hmac_tag,
        "signature": signature,
    }


def bob_process_message(
    artefact: dict,
    aes_key: bytes,
    hmac_key: bytes,
    signing_public_key,
    mode: str,
) -> bytes:
    """Bob verifies and decrypts Alice's protected message."""

    ciphertext = artefact["ciphertext"]
    iv_or_nonce = artefact["iv_or_nonce"]
    hmac_tag = artefact["hmac_tag"]
    signature = artefact["signature"]

    protected_data = iv_or_nonce + ciphertext

    hmac_valid = verify_hmac(
        protected_data,
        hmac_tag,
        hmac_key
    )

    if not hmac_valid:
        raise ValueError("HMAC verification failed.")

    if mode.upper() == "CBC":
        plaintext = decrypt_cbc(
            ciphertext,
            aes_key,
            iv_or_nonce
        )
    elif mode.upper() == "CTR":
        plaintext = decrypt_ctr(
            ciphertext,
            aes_key,
            iv_or_nonce
        )
    else:
        raise ValueError("Mode must be either CBC or CTR.")

    signature_valid = verify_signature(
        plaintext,
        signature,
        signing_public_key
    )

    if not signature_valid:
        raise ValueError("Digital signature verification failed.")

    return plaintext


def run_exchange(message: bytes, mode: str) -> bytes:
    """Run the complete Alice-to-Bob secure exchange."""

    print("Generating Diffie-Hellman parameters...")
    parameters = generate_dh_parameters()

    alice_dh_private, alice_dh_public = generate_dh_key_pair(parameters)
    bob_dh_private, bob_dh_public = generate_dh_key_pair(parameters)

    alice_shared_secret = alice_dh_private.exchange(bob_dh_public)
    bob_shared_secret = bob_dh_private.exchange(alice_dh_public)

    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Diffie-Hellman shared secrets do not match.")

    alice_aes_key, alice_hmac_key = derive_session_keys(
        alice_shared_secret
    )

    bob_aes_key, bob_hmac_key = derive_session_keys(
        bob_shared_secret
    )

    signing_private_key, signing_public_key = generate_signing_key_pair()

    artefact = alice_prepare_message(
        message,
        alice_aes_key,
        alice_hmac_key,
        signing_private_key,
        mode,
    )

    recovered_message = bob_process_message(
        artefact,
        bob_aes_key,
        bob_hmac_key,
        signing_public_key,
        mode,
    )

    print("Diffie-Hellman keys matched.")
    print(f"Mode: AES-{mode.upper()}")
    print(f"Original message length: {len(message)} bytes")
    print(f"Ciphertext length: {len(artefact['ciphertext'])} bytes")
    print(f"IV or nonce length: {len(artefact['iv_or_nonce'])} bytes")
    print(f"HMAC tag length: {len(artefact['hmac_tag'])} bytes")
    print(f"Digital signature length: {len(artefact['signature'])} bytes")
    print(f"Recovered message matches: {recovered_message == message}")

    return recovered_message


def load_input_message(message_text: str | None, file_path: str | None) -> bytes:
    """Load a message from text or from a file."""

    if message_text is not None:
        return message_text.encode("utf-8")

    if file_path is not None:
        return Path(file_path).read_bytes()

    raise ValueError("Provide either --message or --file.")


def main():
    parser = argparse.ArgumentParser(
        description="ICS 344 secure message exchange prototype"
    )

    parser.add_argument(
        "--message",
        help="Text message to protect"
    )

    parser.add_argument(
        "--file",
        help="Path to a file to protect"
    )

    parser.add_argument(
        "--mode",
        choices=["CBC", "CTR"],
        default="CBC",
        help="AES mode to use"
    )

    args = parser.parse_args()

    message = load_input_message(
        args.message,
        args.file
    )

    recovered_message = run_exchange(
        message,
        args.mode
    )

    print(f"Recovered content: {recovered_message.decode('utf-8')}")


if __name__ == "__main__":
    main()