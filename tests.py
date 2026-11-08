from pathlib import Path

from crypto_utils import (
    generate_aes_key,
    encrypt_cbc,
    decrypt_cbc,
    encrypt_ctr,
    decrypt_ctr,
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

    print(f"Plaintext length: {len(message)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"IV length: {len(iv)} bytes")


def test_cbc_unaligned_file():
    test_folder = Path("test_data")
    test_folder.mkdir(exist_ok=True)

    file_path = test_folder / "unaligned_sample.txt"

    file_data = (
        b"This file is intentionally not aligned to the AES block size."
        b" ICS344 student 202262140."
    )

    file_path.write_bytes(file_data)

    original_data = file_path.read_bytes()
    key = generate_aes_key()

    ciphertext, iv = encrypt_cbc(original_data, key)
    recovered_data = decrypt_cbc(ciphertext, key, iv)

    print("\nT02 - AES-CBC unaligned file")

    check(len(original_data) % 16 != 0, "Original file is not block aligned")
    check(recovered_data == original_data, "Recovered file matches original")
    check(len(iv) == 16, "CBC IV is 16 bytes")
    check(len(ciphertext) % 16 == 0, "CBC ciphertext is block aligned")

    print(f"Original file length: {len(original_data)} bytes")
    print(f"CBC ciphertext length: {len(ciphertext)} bytes")
    print(f"CBC IV length: {len(iv)} bytes")


def test_ctr_short_message():
    message = b"ICS344 short message"
    key = generate_aes_key()

    ciphertext, nonce = encrypt_ctr(message, key)
    recovered_message = decrypt_ctr(ciphertext, key, nonce)

    print("\nT03 - AES-CTR short message")

    check(recovered_message == message, "Recovered message matches original")
    check(len(nonce) == 16, "CTR nonce is 16 bytes")
    check(len(ciphertext) == len(message), "CTR ciphertext length equals plaintext length")

    print(f"Plaintext length: {len(message)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Nonce length: {len(nonce)} bytes")


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
    check(len(ciphertext) == len(original_data), "CTR preserves data length")

    print(f"Original file length: {len(original_data)} bytes")
    print(f"CTR ciphertext length: {len(ciphertext)} bytes")
    print(f"CTR nonce length: {len(nonce)} bytes")


if __name__ == "__main__":
    test_cbc_short_message()
    test_cbc_unaligned_file()
    test_ctr_short_message()
    test_ctr_unaligned_file()

    print("\nAll AES-CBC and AES-CTR validation checks completed successfully.")