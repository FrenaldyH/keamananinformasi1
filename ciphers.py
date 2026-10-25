"""AES / DES / RC4 helpers. Every encryption uses a fresh random IV/nonce, never ECB."""
import hashlib
import os

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad

ALGOS = ("aes", "des", "rc4")
KEY_SIZES = {"aes": 32, "des": 8, "rc4": 16}  # AES-256, DES (56 effective bits), RC4-128
KDF_ITERATIONS = 200_000


def derive_keys(password: str, salt: bytes) -> dict:
    """Derive one independent key per algorithm from the user's password (PBKDF2-SHA256)."""
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, KDF_ITERATIONS,
                              dklen=sum(KEY_SIZES.values()))
    keys, i = {}, 0
    for algo in ALGOS:  # slice the long output into per-algorithm keys
        keys[algo] = raw[i:i + KEY_SIZES[algo]]
        i += KEY_SIZES[algo]
    return keys


def _rc4(key: bytes, nonce: bytes):
    """RC4 has no IV, so hash a per-file nonce into the key: no two files share a keystream.
    drop=768 discards the statistically biased first keystream bytes (RC4-drop[768])."""
    return ARC4.new(hashlib.sha256(key + nonce).digest()[:16], drop=768)


def encrypt(algo: str, key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """Encrypt bytes, return (iv_or_nonce, ciphertext)."""
    if algo == "aes":  # AES-256-CBC, 16-byte block -> PKCS#7 pad to 16
        iv = os.urandom(16)
        return iv, AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
    if algo == "des":  # DES-CBC, 8-byte block -> PKCS#7 pad to 8
        iv = os.urandom(8)
        return iv, DES.new(key, DES.MODE_CBC, iv).encrypt(pad(data, 8))
    if algo == "rc4":  # stream cipher: no padding, ciphertext length == plaintext length
        nonce = os.urandom(16)
        return nonce, _rc4(key, nonce).encrypt(data)
    raise ValueError(f"unknown algo {algo}")


def decrypt(algo: str, key: bytes, iv: bytes, data: bytes) -> bytes:
    """Reverse of encrypt()."""
    if algo == "aes":
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)
    if algo == "des":
        return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(data), 8)
    if algo == "rc4":
        return _rc4(key, iv).decrypt(data)
    raise ValueError(f"unknown algo {algo}")


if __name__ == "__main__":
    # Self-check: round-trip, expected sizes, and random IV => same plaintext gives different ciphertext
    keys = derive_keys("password123", os.urandom(16))
    for n in (0, 1, 7, 8, 15, 16, 17, 100_000):
        msg = os.urandom(n)
        for algo in ALGOS:
            iv, ct = encrypt(algo, keys[algo], msg)
            assert decrypt(algo, keys[algo], iv, ct) == msg, (algo, n)
            block = {"aes": 16, "des": 8, "rc4": None}[algo]
            expected = n if block is None else (n // block + 1) * block
            assert len(ct) == expected, (algo, n, len(ct))
            assert encrypt(algo, keys[algo], msg)[1] != ct or n == 0, (algo, n)
    print("ciphers.py self-check OK")
