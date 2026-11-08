from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_utils import (
    generate_aes_key,
    encrypt_ctr,
)


def xor_bytes(first: bytes, second: bytes) -> bytes:
    """Calculate the XOR of two byte strings."""
    return bytes(a ^ b for a, b in zip(first, second))


def encrypt_ctr_with_nonce(
    plaintext: bytes,
    key: bytes,
    nonce: bytes
) -> bytes:
    """Encrypt AES-CTR using a supplied nonce."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce)
    )

    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def check(condition: bool, description: str) -> None:
    """Display a check or failure based on the actual condition."""
    if condition:
        print(f"[✓] {description}")
    else:
        print(f"[✗] {description}")
        raise AssertionError(f"Check failed: {description}")


def run_nonce_reuse_experiment():
    message_one = b"ICS344 message one!"
    message_two = b"ICS344 message two!"

    check(
        len(message_one) == len(message_two),
        "Both messages have equal length"
    )

    key = generate_aes_key()

    print("TASK 3 - AES-CTR NONCE REUSE EXPERIMENT")

    print("\nBaseline: fresh nonce for every encryption")

    ciphertext_one, nonce_one = encrypt_ctr(message_one, key)
    ciphertext_two, nonce_two = encrypt_ctr(message_two, key)

    check(
        nonce_one != nonce_two,
        "Baseline messages use different nonces"
    )

    baseline_ciphertext_xor = xor_bytes(
        ciphertext_one,
        ciphertext_two
    )

    baseline_plaintext_xor = xor_bytes(
        message_one,
        message_two
    )

    check(
        baseline_ciphertext_xor != baseline_plaintext_xor,
        "Fresh nonces prevent the nonce-reuse relationship"
    )

    print(f"Baseline nonce one: {nonce_one.hex()}")
    print(f"Baseline nonce two: {nonce_two.hex()}")
    print(
        "Baseline ciphertext XOR equals plaintext XOR: "
        f"{baseline_ciphertext_xor == baseline_plaintext_xor}"
    )

    print("\nControlled misuse: same nonce reused with the same key")

    reused_nonce = nonce_one

    reused_ciphertext_one = encrypt_ctr_with_nonce(
        message_one,
        key,
        reused_nonce
    )

    reused_ciphertext_two = encrypt_ctr_with_nonce(
        message_two,
        key,
        reused_nonce
    )

    reused_ciphertext_xor = xor_bytes(
        reused_ciphertext_one,
        reused_ciphertext_two
    )

    check(
        reused_ciphertext_xor == baseline_plaintext_xor,
        "Nonce reuse exposes the XOR relationship between plaintexts"
    )

    print(f"Reused nonce: {reused_nonce.hex()}")
    print(
        "Misuse ciphertext XOR equals plaintext XOR: "
        f"{reused_ciphertext_xor == baseline_plaintext_xor}"
    )

    print("\nCorrection: use a fresh nonce for every encryption")

    corrected_ciphertext_one, corrected_nonce_one = encrypt_ctr(
        message_one,
        key
    )

    corrected_ciphertext_two, corrected_nonce_two = encrypt_ctr(
        message_two,
        key
    )

    corrected_ciphertext_xor = xor_bytes(
        corrected_ciphertext_one,
        corrected_ciphertext_two
    )

    check(
        corrected_nonce_one != corrected_nonce_two,
        "Corrected messages use different nonces"
    )

    check(
        corrected_ciphertext_xor != baseline_plaintext_xor,
        "Fresh nonces remove the observed XOR relationship"
    )

    print(f"Corrected nonce one: {corrected_nonce_one.hex()}")
    print(f"Corrected nonce two: {corrected_nonce_two.hex()}")
    print(
        "Corrected ciphertext XOR equals plaintext XOR: "
        f"{corrected_ciphertext_xor == baseline_plaintext_xor}"
    )

    print("\nAll nonce-reuse experiment checks completed successfully.")


if __name__ == "__main__":
    run_nonce_reuse_experiment()