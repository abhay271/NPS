import sys
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from crypto_utils import (
    compute_dh_shared_secret,
    generate_dh_private_key,
    generate_rsa_keypair,
    get_dh_public_value,
    save_keys,
)


DH_STATE_DIR = Path("dh_state")
KEYS_DIR = Path("keys")


def _ensure_dirs():
    DH_STATE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _save_dh_private_key(path: Path, private_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(private_bytes)


def _load_dh_private_key(path: Path):
    return serialization.load_pem_private_key(
        path.read_bytes(), password=None, backend=default_backend()
    )


def _read_peer_public_value(path: Path) -> int:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"Empty DH public value in {path}")
    return int(value)


def gen_receiver():
    _ensure_dirs()
    private_key = generate_dh_private_key()
    public_value = get_dh_public_value(private_key)

    _save_dh_private_key(DH_STATE_DIR / "receiver_dh_priv.bin", private_key)
    (DH_STATE_DIR / "receiver_dh_pub.txt").write_text(str(public_value), encoding="utf-8")
    print("receiver DH generated")


def compute_receiver():
    _ensure_dirs()
    private_key = _load_dh_private_key(DH_STATE_DIR / "receiver_dh_priv.bin")
    peer_public = _read_peer_public_value(DH_STATE_DIR / "sender_dh_pub.txt")
    aes_key = compute_dh_shared_secret(private_key, peer_public)
    (DH_STATE_DIR / "aes_key.bin").write_bytes(aes_key)
    print("receiver AES key derived")


def compute_sender():
    _ensure_dirs()
    private_key = _load_dh_private_key(DH_STATE_DIR / "sender_dh_priv.bin")
    peer_public = _read_peer_public_value(DH_STATE_DIR / "receiver_dh_pub.txt")
    aes_key = compute_dh_shared_secret(private_key, peer_public)
    (DH_STATE_DIR / "aes_key.bin").write_bytes(aes_key)
    print("sender AES key derived")


def gen_sender():
    _ensure_dirs()
    private_key = generate_dh_private_key()
    public_value = get_dh_public_value(private_key)

    _save_dh_private_key(DH_STATE_DIR / "sender_dh_priv.bin", private_key)
    (DH_STATE_DIR / "sender_dh_pub.txt").write_text(str(public_value), encoding="utf-8")
    compute_sender()
    print("sender DH generated")


def gen_rsa():
    _ensure_dirs()
    private_key, public_key = generate_rsa_keypair()
    save_keys(private_key, public_key, key_dir=str(KEYS_DIR))
    print("RSA keypair generated")


def main():
    if len(sys.argv) != 2:
        print("Usage: python dh_helper.py <gen_receiver|gen_sender|compute_receiver|compute_sender|gen_rsa>")
        sys.exit(1)

    cmd = sys.argv[1]
    actions = {
        "gen_receiver": gen_receiver,
        "gen_sender": gen_sender,
        "compute_receiver": compute_receiver,
        "compute_sender": compute_sender,
        "gen_rsa": gen_rsa,
    }

    action = actions.get(cmd)
    if action is None:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    action()


if __name__ == "__main__":
    main()
