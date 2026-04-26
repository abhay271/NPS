import base64
import hashlib
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 3526 Group 14 (2048-bit MODP) prime and generator
RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA18217C32905E462E36CE3BE39E772C180E86039B2783"
    "A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C"
    "EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_GROUP14_G = 2


def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(private_key_pem: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(
        private_key_pem,
        password=password,
        backend=default_backend(),
    )


def load_public_key(public_key_pem: bytes):
    return serialization.load_pem_public_key(public_key_pem, backend=default_backend())


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def save_keys(private_key, public_key, key_dir: str = "keys") -> Tuple[str, str]:
    Path(key_dir).mkdir(parents=True, exist_ok=True)
    private_path = str(Path(key_dir) / "private.pem")
    public_path = str(Path(key_dir) / "public.pem")

    with open(private_path, "wb") as f:
        f.write(serialize_private_key(private_key))

    with open(public_path, "wb") as f:
        f.write(serialize_public_key(public_key))

    return private_path, public_path


def load_keys(
    private_path: str = "keys/private.pem", public_path: str = "keys/public.pem"
):
    with open(private_path, "rb") as f:
        private_key = load_private_key(f.read())

    with open(public_path, "rb") as f:
        public_key = load_public_key(f.read())

    return private_key, public_key


def _dh_parameters():
    parameter_numbers = dh.DHParameterNumbers(RFC3526_GROUP14_P, RFC3526_GROUP14_G)
    return parameter_numbers.parameters(default_backend())


def generate_dh_private_key():
    return _dh_parameters().generate_private_key()


def get_dh_public_value(dh_private_key) -> int:
    return dh_private_key.public_key().public_numbers().y


def compute_dh_shared_secret(dh_private_key, peer_public_value: int) -> bytes:
    params = _dh_parameters()
    peer_public_numbers = dh.DHPublicNumbers(peer_public_value, params.parameter_numbers())
    peer_public_key = peer_public_numbers.public_key(default_backend())

    raw_shared_secret = dh_private_key.exchange(peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dual-layer-secure-comms-aes-key",
        backend=default_backend(),
    ).derive(raw_shared_secret)

    return derived_key


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def aes_encrypt(aes_key: bytes, plaintext_bytes: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")

    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext_bytes)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def aes_decrypt(aes_key: bytes, iv_and_ciphertext: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    if len(iv_and_ciphertext) < 32:
        raise ValueError("Ciphertext too short")

    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return _pkcs7_unpad(padded_plaintext)


def dual_encrypt(message_str: str, rsa_public_key, aes_key: bytes) -> dict:
    plaintext_bytes = message_str.encode("utf-8")
    rsa_ciphertext = rsa_encrypt(rsa_public_key, plaintext_bytes)
    aes_ciphertext = aes_encrypt(aes_key, rsa_ciphertext)

    return {
        "original": message_str,
        "rsa_ciphertext_b64": base64.b64encode(rsa_ciphertext).decode("ascii"),
        "aes_ciphertext_b64": base64.b64encode(aes_ciphertext).decode("ascii"),
        "aes_ciphertext_bytes": aes_ciphertext,
    }


def dual_decrypt(aes_ciphertext_bytes: bytes, rsa_private_key, aes_key: bytes) -> str:
    rsa_ciphertext = aes_decrypt(aes_key, aes_ciphertext_bytes)
    plaintext_bytes = rsa_decrypt(rsa_private_key, rsa_ciphertext)
    return plaintext_bytes.decode("utf-8")


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _print_result(step: str, ok: bool, detail: str):
    status = "PASS" if ok else "FAIL"
    print(f"{step:<32} [{status}] {detail}")


if __name__ == "__main__":
    all_ok = True

    try:
        print("[1] RSA Key Generation...")
        priv, pub = generate_rsa_keypair()
        test_msg = b"rsa test"
        rsa_ct = rsa_encrypt(pub, test_msg)
        rsa_pt = rsa_decrypt(priv, rsa_ct)
        ok = rsa_pt == test_msg
        _print_result("RSA keygen/encrypt/decrypt", ok, "RSA flow validated")
        all_ok = all_ok and ok
    except Exception as exc:
        _print_result("RSA keygen/encrypt/decrypt", False, str(exc))
        all_ok = False

    try:
        print("[2] Diffie-Hellman Key Exchange...")
        alice_priv = generate_dh_private_key()
        bob_priv = generate_dh_private_key()
        alice_pub = get_dh_public_value(alice_priv)
        bob_pub = get_dh_public_value(bob_priv)

        alice_key = compute_dh_shared_secret(alice_priv, bob_pub)
        bob_key = compute_dh_shared_secret(bob_priv, alice_pub)
        ok = alice_key == bob_key and len(alice_key) == 32
        _print_result("DH shared secret + HKDF", ok, "Derived matching 32-byte keys")
        all_ok = all_ok and ok
    except Exception as exc:
        _print_result("DH shared secret + HKDF", False, str(exc))
        all_ok = False

    try:
        print("[3] AES-256-CBC...")
        aes_key = os.urandom(32)
        plain = b"AES CBC test payload"
        enc = aes_encrypt(aes_key, plain)
        dec = aes_decrypt(aes_key, enc)
        ok = dec == plain
        _print_result("AES encrypt/decrypt", ok, "CBC with PKCS7 validated")
        all_ok = all_ok and ok
    except Exception as exc:
        _print_result("AES encrypt/decrypt", False, str(exc))
        all_ok = False

    try:
        print("[4] Dual Encryption...")
        priv2, pub2 = generate_rsa_keypair()
        aes_key2 = os.urandom(32)
        message = "Hello secure world"
        wrapped = dual_encrypt(message, pub2, aes_key2)
        recovered = dual_decrypt(wrapped["aes_ciphertext_bytes"], priv2, aes_key2)
        ok = recovered == message
        _print_result("Dual encrypt/decrypt", ok, "RSA wrapped by AES validated")
        all_ok = all_ok and ok
    except Exception as exc:
        _print_result("Dual encrypt/decrypt", False, str(exc))
        all_ok = False

    try:
        print("[5] SHA-256...")
        sample = b"sha256 sample"
        digest_bytes = sha256_bytes(sample)
        expected = hashlib.sha256(sample).hexdigest()
        ok = digest_bytes == expected
        _print_result("SHA-256 bytes", ok, "Hash function validated")
        all_ok = all_ok and ok
    except Exception as exc:
        _print_result("SHA-256 bytes", False, str(exc))
        all_ok = False

    print("All tests passed!" if all_ok else "One or more tests failed.")
