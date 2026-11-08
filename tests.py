from pathlib import Path

from crypto_utils import generate_aes_key, encrypt_cbc, decrypt_cbc


def test_cbc_short_message():
    message = b"ICS344 short message"
    key = generate_aes_key()

    ciphertext, iv = encrypt_cbc(message, key)
    recovered_message = decrypt_cbc(ciphertext, key, iv)

    assert recovered_message == message

    print("T01 - AES-CBC short message round trip: PASS")
    print(f"Plaintext length: {len(message)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"IV length: {len(iv)} bytes")
    print(f"Recovered correctly: {recovered_message == message}")


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

    assert len(original_data) % 16 != 0
    assert recovered_data == original_data

    print("\nT02 - AES-CBC unaligned file round trip: PASS")
    print(f"Original file length: {len(original_data)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"IV length: {len(iv)} bytes")
    print(
        f"Original size aligned to 16 bytes: "
        f"{len(original_data) % 16 == 0}"
    )
    print(f"Recovered correctly: {recovered_data == original_data}")


if __name__ == "__main__":
    test_cbc_short_message()
    test_cbc_unaligned_file()