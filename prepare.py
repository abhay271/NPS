import argparse
import json
from pathlib import Path

from crypto_utils import dual_encrypt, load_public_key, sha256_file
from steg import embed, get_pixel_diff


def run(message: str) -> dict:
    public_key_path = Path("keys/public.pem")
    aes_key_path = Path("dh_state/aes_key.bin")
    cover_image_path = Path("images/cover.png")
    stego_image_path = Path("output/stego.png")
    hash_path = Path("output/hash.txt")

    if not public_key_path.exists():
        raise FileNotFoundError(f"Missing RSA public key: {public_key_path}")
    if not aes_key_path.exists():
        raise FileNotFoundError(f"Missing AES key file: {aes_key_path}")
    if not cover_image_path.exists():
        raise FileNotFoundError(f"Missing cover image: {cover_image_path}")

    rsa_public_key = load_public_key(public_key_path.read_bytes())
    aes_key = aes_key_path.read_bytes()
    if len(aes_key) != 32:
        raise ValueError("AES key must be exactly 32 bytes")

    encrypted = dual_encrypt(message, rsa_public_key, aes_key)

    stego_image_path.parent.mkdir(parents=True, exist_ok=True)
    hash_path.parent.mkdir(parents=True, exist_ok=True)

    embed(str(cover_image_path), encrypted["aes_ciphertext_bytes"], str(stego_image_path))

    sha256_hash = sha256_file(str(stego_image_path))
    hash_path.write_text(sha256_hash, encoding="utf-8")

    pixel_diff = get_pixel_diff(str(cover_image_path), str(stego_image_path), sample_count=8)

    return {
        "status": "success",
        "original_message": message,
        "rsa_ciphertext_b64": encrypted["rsa_ciphertext_b64"],
        "aes_ciphertext_b64": encrypted["aes_ciphertext_b64"],
        "sha256_hash": sha256_hash,
        "stego_image_path": str(stego_image_path),
        "pixel_diff": pixel_diff,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sender pre-processing pipeline")
    parser.add_argument("--message", required=True, help="Secret message to protect")
    args = parser.parse_args()

    try:
        result = run(args.message)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=True, separators=(",", ":")))
