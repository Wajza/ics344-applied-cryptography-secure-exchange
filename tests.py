from pathlib import Path

from crypto_utils import (
    generate_aes_key,
    encrypt_cbc,
    decrypt_cbc,
    encrypt_ctr,
    decrypt_ctr,
    generate_hmac_key,
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

from misuse_experiment import (
    encrypt_ctr_with_nonce,
    xor_bytes,
)


def check(condition: bool, description: str) -> None:
    """Display a check or failure based on the actual condition."""
    if condition:
        print(f"[✓] {description}")
    else:
        print(f"[✗] {description}")
        raise AssertionError(f"Check failed: {description}")


def test_cbc_short_message():
    message = b"ICS344 short message"
    key = generate_aes_key()

    ciphertext, iv = encrypt_cbc(message, key)
    recovered_message = decrypt_cbc(ciphertext, key, iv)

    print("T01 - AES-CBC short message")

    check(recovered_message == message, "Recovered message matches original")
    check(len(iv) == 16, "CBC IV is 16 bytes")
    check(len(ciphertext) % 16 == 0, "CBC ciphertext is block aligned")


def test_cbc_unaligned_file():
    file_path = Path("test_data") / "unaligned_sample.txt"
    original_data = file_path.read_bytes()
    key = generate_aes_key()

    ciphertext, iv = encrypt_cbc(original_data, key)
    recovered_data = decrypt_cbc(ciphertext, key, iv)

    print("\nT02 - AES-CBC unaligned file")

    check(len(original_data) % 16 != 0, "Original file is not block aligned")
    check(recovered_data == original_data, "Recovered file matches original")
    check(len(iv) == 16, "CBC IV is 16 bytes")
    check(len(ciphertext) % 16 == 0, "CBC ciphertext is block aligned")


def test_ctr_short_message():
    message = b"ICS344 short message"
    key = generate_aes_key()

    ciphertext, nonce = encrypt_ctr(message, key)
    recovered_message = decrypt_ctr(ciphertext, key, nonce)

    print("\nT03 - AES-CTR short message")

    check(recovered_message == message, "Recovered message matches original")
    check(len(nonce) == 16, "CTR nonce is 16 bytes")
    check(
        len(ciphertext) == len(message),
        "CTR ciphertext length equals plaintext length"
    )


def test_ctr_unaligned_file():
    file_path = Path("test_data") / "unaligned_sample.txt"
    original_data = file_path.read_bytes()
    key = generate_aes_key()

    ciphertext, nonce = encrypt_ctr(original_data, key)
    recovered_data = decrypt_ctr(ciphertext, key, nonce)

    print("\nT04 - AES-CTR unaligned file")

    check(len(original_data) % 16 != 0, "Original file is not block aligned")
    check(recovered_data == original_data, "Recovered file matches original")
    check(len(nonce) == 16, "CTR nonce is 16 bytes")
    check(
        len(ciphertext) == len(original_data),
        "CTR preserves data length"
    )


def test_hmac_valid_message():
    message = b"ICS344 message protected by HMAC"
    encryption_key = generate_aes_key()
    hmac_key = generate_hmac_key()

    ciphertext, iv = encrypt_cbc(message, encryption_key)
    protected_data = iv + ciphertext

    tag = create_hmac(protected_data, hmac_key)
    verification_result = verify_hmac(
        protected_data,
        tag,
        hmac_key
    )

    print("\nT05 - HMAC valid message")

    check(verification_result is True, "Valid HMAC is accepted")
    check(len(hmac_key) == 32, "HMAC key is 32 bytes")
    check(len(tag) == 32, "HMAC-SHA-256 tag is 32 bytes")


def test_hmac_modified_message():
    message = b"ICS344 message protected by HMAC"
    encryption_key = generate_aes_key()
    hmac_key = generate_hmac_key()

    ciphertext, iv = encrypt_cbc(message, encryption_key)
    protected_data = iv + ciphertext

    tag = create_hmac(protected_data, hmac_key)

    modified_data = bytearray(protected_data)
    modified_data[-1] ^= 1
    modified_data = bytes(modified_data)

    verification_result = verify_hmac(
        modified_data,
        tag,
        hmac_key
    )

    print("\nT06 - HMAC modified message")

    check(
        verification_result is False,
        "Modified protected data is rejected"
    )


def test_diffie_hellman_key_establishment():
    parameters = generate_dh_parameters()

    alice_private_key, alice_public_key = generate_dh_key_pair(parameters)
    bob_private_key, bob_public_key = generate_dh_key_pair(parameters)

    alice_shared_secret = derive_shared_secret(
        alice_private_key,
        bob_public_key
    )

    bob_shared_secret = derive_shared_secret(
        bob_private_key,
        alice_public_key
    )

    alice_aes_key, alice_hmac_key = derive_session_keys(
        alice_shared_secret
    )

    bob_aes_key, bob_hmac_key = derive_session_keys(
        bob_shared_secret
    )

    print("\nT07 - Diffie-Hellman key establishment")

    check(
        alice_shared_secret == bob_shared_secret,
        "Alice and Bob derived the same shared secret"
    )

    check(
        alice_aes_key == bob_aes_key,
        "Alice and Bob derived the same AES key"
    )

    check(
        alice_hmac_key == bob_hmac_key,
        "Alice and Bob derived the same HMAC key"
    )

    check(
        alice_aes_key != alice_hmac_key,
        "AES and HMAC keys are separate"
    )


def test_valid_digital_signature():
    message = b"ICS344 digitally signed message"

    private_key, public_key = generate_signing_key_pair()
    signature = sign_message(message, private_key)

    verification_result = verify_signature(
        message,
        signature,
        public_key
    )

    print("\nT08 - Valid digital signature")

    check(
        verification_result is True,
        "Unmodified message signature is accepted"
    )

    check(
        len(signature) > 0,
        "Digital signature was generated"
    )


def test_modified_message_signature():
    message = b"ICS344 digitally signed message"
    modified_message = b"ICS344 modified signed message"

    private_key, public_key = generate_signing_key_pair()
    signature = sign_message(message, private_key)

    verification_result = verify_signature(
        modified_message,
        signature,
        public_key
    )

    print("\nT09 - Modified message digital signature")

    check(
        verification_result is False,
        "Modified message signature is rejected"
    )


def test_repeated_message_behavior():
    message = b"ICS344 repeated message"
    key = generate_aes_key()

    ciphertext_one, nonce_one = encrypt_ctr(message, key)
    ciphertext_two, nonce_two = encrypt_ctr(message, key)

    print("\nT10 - Repeated-message behaviour")

    check(
        nonce_one != nonce_two,
        "Repeated messages use different nonces"
    )

    check(
        ciphertext_one != ciphertext_two,
        "Repeated messages produce different ciphertexts"
    )

    check(
        decrypt_ctr(ciphertext_one, key, nonce_one) == message,
        "First repeated message decrypts correctly"
    )

    check(
        decrypt_ctr(ciphertext_two, key, nonce_two) == message,
        "Second repeated message decrypts correctly"
    )


def test_incorrect_key_behavior():
    message = b"ICS344 incorrect key test"
    correct_key = generate_aes_key()
    incorrect_key = generate_aes_key()

    ciphertext, iv = encrypt_cbc(message, correct_key)

    decryption_failed = False

    try:
        decrypt_cbc(ciphertext, incorrect_key, iv)
    except Exception:
        decryption_failed = True

    print("\nT11 - Incorrect-key behaviour")

    check(
        decryption_failed,
        "Decryption with an incorrect key is rejected"
    )


def test_nonce_reuse_misuse():
    message_one = b"ICS344 message one!"
    message_two = b"ICS344 message two!"

    key = generate_aes_key()

    _, reused_nonce = encrypt_ctr(message_one, key)

    ciphertext_one = encrypt_ctr_with_nonce(
        message_one,
        key,
        reused_nonce
    )

    ciphertext_two = encrypt_ctr_with_nonce(
        message_two,
        key,
        reused_nonce
    )

    ciphertext_xor = xor_bytes(
        ciphertext_one,
        ciphertext_two
    )

    plaintext_xor = xor_bytes(
        message_one,
        message_two
    )

    print("\nT12 - CTR nonce-reuse misuse")

    check(
        ciphertext_xor == plaintext_xor,
        "Nonce reuse exposes the plaintext XOR relationship"
    )


if __name__ == "__main__":
    test_cbc_short_message()
    test_cbc_unaligned_file()
    test_ctr_short_message()
    test_ctr_unaligned_file()
    test_hmac_valid_message()
    test_hmac_modified_message()
    test_diffie_hellman_key_establishment()
    test_valid_digital_signature()
    test_modified_message_signature()
    test_repeated_message_behavior()
    test_incorrect_key_behavior()
    test_nonce_reuse_misuse()

    print(
        "\nAll comparative security testing checks completed successfully."
    )