import json
from pathlib import Path

from crypto_utils import dual_decrypt, load_private_key, sha256_file
from steg import extract


def run() -> dict:
    stego_path = Path("received/stego.png")
    hash_path = Path("received/hash.txt")
    aes_key_path = Path("dh_state/aes_key.bin")
    private_key_path = Path("keys/private.pem")

    if not stego_path.exists():
        raise FileNotFoundError(f"Missing received stego image: {stego_path}")
    if not hash_path.exists():
        raise FileNotFoundError(f"Missing received hash file: {hash_path}")
    if not aes_key_path.exists():
        raise FileNotFoundError(f"Missing AES key file: {aes_key_path}")
    if not private_key_path.exists():
        raise FileNotFoundError(f"Missing RSA private key: {private_key_path}")

    sha256_expected = hash_path.read_text(encoding="utf-8").strip()
    sha256_actual = sha256_file(str(stego_path))

    if sha256_expected != sha256_actual:
        return {
            "status": "tampered",
            "hash_verified": False,
            "sha256_expected": sha256_expected,
            "sha256_actual": sha256_actual,
        }

    ciphertext = extract(str(stego_path))

    aes_key = aes_key_path.read_bytes()
    if len(aes_key) != 32:
        raise ValueError("AES key must be exactly 32 bytes")

    rsa_private_key = load_private_key(private_key_path.read_bytes())
    decrypted_message = dual_decrypt(ciphertext, rsa_private_key, aes_key)

    return {
        "status": "success",
        "hash_verified": True,
        "decrypted_message": decrypted_message,
        "sha256_expected": sha256_expected,
        "sha256_actual": sha256_actual,
    }


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=True, separators=(",", ":")))
