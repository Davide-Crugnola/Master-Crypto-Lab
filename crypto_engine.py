import base64
import os
import math
import hashlib
import hmac as hmac_module
from typing import Tuple, Optional, Callable, Dict

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms as _alg, modes
from cryptography.hazmat.primitives import padding

# TripleDES may be in 'decrepit' module in newer cryptography versions
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES, Blowfish
except ImportError:
    TripleDES = _alg.TripleDES
    from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish

from .config import PBKDF2_ITERATIONS

# ---------------------------------------------------------------------------
# Cipher Registry
# ---------------------------------------------------------------------------

CIPHER_REGISTRY: dict = {}
"""Registry structure:
  name -> {
    "key_size": int or None,        # default key size in bytes (None = variable)
    "generate_key": Callable[[], bytes],
    "encrypt": Callable[[bytes, bytes], bytes],
    "decrypt": Callable[[bytes, bytes], bytes],
    "key_to_str": Callable[[bytes], str],
    "str_to_key": Callable[[str], bytes],
    "ciphertext_format": str,       # "base64" | "hex" | "raw"
    "educational": bool,
    "description": str,
  }
"""


def _make_cbc_hmac_key(aes_key_size: int = 32) -> Tuple[int, Callable, Callable, Callable]:
    """Factory for AES-CBC + HMAC-SHA256 encrypt-then-MAC ciphers."""
    hmac_key_size = 32
    total_key_size = aes_key_size + hmac_key_size

    def generate_key() -> bytes:
        return os.urandom(total_key_size)

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        aes_key = key[:aes_key_size]
        mac_key = key[aes_key_size:]
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(_alg.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        h = hmac_module.new(mac_key, iv + ct, hashlib.sha256)
        return iv + ct + h.digest()

    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        aes_key = key[:aes_key_size]
        mac_key = key[aes_key_size:]
        iv = ciphertext[:16]
        ct = ciphertext[16:-32]
        expected_mac = ciphertext[-32:]
        h = hmac_module.new(mac_key, iv + ct, hashlib.sha256)
        if not hmac_module.compare_digest(h.digest(), expected_mac):
            raise ValueError("HMAC authentication failed — ciphertext may be tampered.")
        cipher = Cipher(_alg.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    return total_key_size, generate_key, encrypt, decrypt


# ---- 1. Fernet (AES-128-CBC + HMAC) ----
CIPHER_REGISTRY["Fernet (AES-128-CBC + HMAC)"] = {
    "key_size": 32,
    "generate_key": Fernet.generate_key,
    "encrypt": lambda k, p: Fernet(k).encrypt(p),
    "decrypt": lambda k, c: Fernet(k).decrypt(c),
    "key_to_str": lambda k: k.decode(),
    "str_to_key": lambda s: s.encode(),
    "ciphertext_format": "base64",
    "educational": False,
    "description": "Standard Fernet (AES-128-CBC + HMAC-SHA256, base64-urlsafe key)",
}

# ---- 2. AES-256-GCM ----
CIPHER_REGISTRY["AES-256-GCM"] = {
    "key_size": 32,
    "generate_key": lambda: AESGCM.generate_key(bit_length=256),
    "encrypt": lambda k, p: _aesgcm_encrypt(k, p),
    "decrypt": lambda k, c: _aesgcm_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-GCM authenticated encryption (nonce 12B + ciphertext)",
}


def _aesgcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def _aesgcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(ciphertext[:12], ciphertext[12:], None)


# ---- 3. ChaCha20-Poly1305 ----
CIPHER_REGISTRY["ChaCha20-Poly1305"] = {
    "key_size": 32,
    "generate_key": lambda: ChaCha20Poly1305.generate_key(),
    "encrypt": lambda k, p: _chacha_encrypt(k, p),
    "decrypt": lambda k, c: _chacha_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "ChaCha20-Poly1305 AEAD (fast, modern, nonce 12B + ciphertext)",
}


def _chacha_encrypt(key: bytes, plaintext: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return nonce + chacha.encrypt(nonce, plaintext, None)


def _chacha_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(ciphertext[:12], ciphertext[12:], None)


# ---- 4. AES-256-CBC + HMAC-SHA256 ----
_ksz4, _gen4, _enc4, _dec4 = _make_cbc_hmac_key(aes_key_size=32)
CIPHER_REGISTRY["AES-256-CBC + HMAC-SHA256"] = {
    "key_size": _ksz4,
    "generate_key": _gen4,
    "encrypt": _enc4,
    "decrypt": _dec4,
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-CBC with PKCS7 padding + HMAC-SHA256 (encrypt-then-MAC, 64B key)",
}

# ---- 5. AES-128-GCM ----
CIPHER_REGISTRY["AES-128-GCM"] = {
    "key_size": 16,
    "generate_key": lambda: AESGCM.generate_key(bit_length=128),
    "encrypt": lambda k, p: _aesgcm_encrypt(k, p),
    "decrypt": lambda k, c: _aesgcm_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-128-GCM authenticated encryption (128-bit key)",
}

# ---- 6. AES-128-CBC + HMAC-SHA256 ----
_ksz6, _gen6, _enc6, _dec6 = _make_cbc_hmac_key(aes_key_size=16)
CIPHER_REGISTRY["AES-128-CBC + HMAC-SHA256"] = {
    "key_size": _ksz6,
    "generate_key": _gen6,
    "encrypt": _enc6,
    "decrypt": _dec6,
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-128-CBC with PKCS7 padding + HMAC-SHA256 (48B key)",
}

# ---- 7. TripleDES (educational - weak) ----
CIPHER_REGISTRY["TripleDES (educational)"] = {
    "key_size": 24,
    "generate_key": lambda: os.urandom(24),
    "encrypt": lambda k, p: _tdes_encrypt(k, p),
    "decrypt": lambda k, c: _tdes_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": True,
    "description": "TripleDES CBC — **legacy, weak**, 56-bit effective security (educational only)",
}


def _tdes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(8)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()


def _tdes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:8]
    ct = ciphertext[8:]
    cipher = Cipher(TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---- 8. Blowfish (legacy - educational) ----
CIPHER_REGISTRY["Blowfish (educational)"] = {
    "key_size": 16,
    "generate_key": lambda: os.urandom(16),
    "encrypt": lambda k, p: _blowfish_encrypt(k, p),
    "decrypt": lambda k, c: _blowfish_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": True,
    "description": "Blowfish CBC — **legacy 64-bit block cipher**, for educational use only",
}


def _blowfish_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(8)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(Blowfish(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()


def _blowfish_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:8]
    ct = ciphertext[8:]
    cipher = Cipher(Blowfish(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---- 9. XOR + HMAC-SHA256 (educational) ----
CIPHER_REGISTRY["XOR + HMAC (educational)"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": lambda k, p: _xorhmac_encrypt(k, p),
    "decrypt": lambda k, c: _xorhmac_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": True,
    "description": "XOR with SHA-256 keystream + HMAC — **trivially broken**, educational",
}


def _xorhmac_keystream(key: bytes, length: int) -> bytes:
    result = b""
    counter = 0
    while len(result) < length:
        result += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return result[:length]


def _xorhmac_encrypt(key: bytes, plaintext: bytes) -> bytes:
    ks = _xorhmac_keystream(key, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    mac = hmac_module.new(key, ct, hashlib.sha256).digest()
    return ct + mac


def _xorhmac_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    ct = ciphertext[:-32]
    expected_mac = ciphertext[-32:]
    mac = hmac_module.new(key, ct, hashlib.sha256).digest()
    if not hmac_module.compare_digest(mac, expected_mac):
        raise ValueError("HMAC authentication failed.")
    ks = _xorhmac_keystream(key, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# ---- 10. Vigenère (educational - trivial) ----
CIPHER_REGISTRY["Vigenère (educational)"] = {
    "key_size": None,
    "generate_key": lambda: os.urandom(16),
    "encrypt": lambda k, p: _vigenere_encrypt(k, p),
    "decrypt": lambda k, c: _vigenere_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": True,
    "description": "Vigenère cipher — **classical, trivial to break**, no authentication",
}


def _vigenere_transform(key: bytes, data: bytes, decrypt_mode: bool = False) -> bytes:
    result = bytearray()
    for i, byte in enumerate(data):
        k = key[i % len(key)]
        if decrypt_mode:
            result.append((byte - k) % 256)
        else:
            result.append((byte + k) % 256)
    return bytes(result)


def _vigenere_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return _vigenere_transform(key, plaintext, decrypt_mode=False)


def _vigenere_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return _vigenere_transform(key, ciphertext, decrypt_mode=True)


# ---- 11. AES-256-CTR ----
CIPHER_REGISTRY["AES-256-CTR"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": lambda k, p: _aes_ctr_encrypt(k, p),
    "decrypt": lambda k, c: _aes_ctr_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-CTR stream mode (nonce 16B + keystream XOR, no padding)",
}


def _aes_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(16)
    cipher = Cipher(_alg.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(plaintext) + encryptor.finalize()


def _aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(_alg.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


# ---- 12. AES-256-OFB ----
CIPHER_REGISTRY["AES-256-OFB"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": lambda k, p: _aes_ofb_encrypt(k, p),
    "decrypt": lambda k, c: _aes_ofb_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-OFB stream mode (IV 16B, output-feedback)",
}


def _aes_ofb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(_alg.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def _aes_ofb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(_alg.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


# ---- 13. AES-256-CFB ----
CIPHER_REGISTRY["AES-256-CFB"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": lambda k, p: _aes_cfb_encrypt(k, p),
    "decrypt": lambda k, c: _aes_cfb_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-CFB stream mode (IV 16B, cipher-feedback)",
}


def _aes_cfb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(_alg.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def _aes_cfb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(_alg.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


# ---- 14. ChaCha20 (pure stream, no Poly1305) ----
CIPHER_REGISTRY["ChaCha20 (stream)"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": lambda k, p: _chacha20_stream_encrypt(k, p),
    "decrypt": lambda k, c: _chacha20_stream_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "ChaCha20 pure stream cipher (nonce 16B, no authentication)",
}


def _chacha20_stream_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(16)
    algorithm = _alg.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(plaintext) + encryptor.finalize()


def _chacha20_stream_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce, ct = ciphertext[:16], ciphertext[16:]
    algorithm = _alg.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


# ---- 15. Hybrid RSA-2048-OAEP + AES-256-GCM ----
# Key is a serialized RSA private key PEM (or public for encrypt-only demo).
# For simplicity the "key" stored in session is the AES session key after unwrap,
# and encrypt packages: RSA-encrypted AES-key || AES-GCM(nonce+ct).

def _hybrid_generate_key() -> bytes:
    """Generate RSA-2048 private key PEM bytes (acts as long-term key material)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _hybrid_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """key = RSA private PEM; encrypt with public part, include wrapped AES key."""
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
    from cryptography.hazmat.primitives import serialization, hashes as hsh
    priv = serialization.load_pem_private_key(key, password=None)
    pub = priv.public_key()
    aes_key = AESGCM.generate_key(bit_length=256)
    wrapped = pub.encrypt(
        aes_key,
        asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
    )
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    # format: 2B len_wrapped | wrapped | nonce(12) | ct
    return len(wrapped).to_bytes(2, "big") + wrapped + nonce + ct


def _hybrid_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
    from cryptography.hazmat.primitives import serialization, hashes as hsh
    priv = serialization.load_pem_private_key(key, password=None)
    wlen = int.from_bytes(ciphertext[:2], "big")
    wrapped = ciphertext[2:2 + wlen]
    rest = ciphertext[2 + wlen:]
    aes_key = priv.decrypt(
        wrapped,
        asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
    )
    nonce, ct = rest[:12], rest[12:]
    return AESGCM(aes_key).decrypt(nonce, ct, None)


CIPHER_REGISTRY["Hybrid RSA-OAEP + AES-GCM"] = {
    "key_size": None,  # variable PEM
    "generate_key": _hybrid_generate_key,
    "encrypt": _hybrid_encrypt,
    "decrypt": _hybrid_decrypt,
    "key_to_str": lambda k: k.decode() if isinstance(k, bytes) else str(k),
    "str_to_key": lambda s: s.encode() if isinstance(s, str) else s,
    "ciphertext_format": "hex",
    "educational": False,
    "description": "Hybrid: RSA-2048-OAEP wraps AES-256-GCM session key (real-world pattern)",
}


# ---- 16. AES-256-XTS (disk / volume encryption style) ----
CIPHER_REGISTRY["AES-256-XTS"] = {
    "key_size": 64,  # two AES-256 keys concatenated
    "generate_key": lambda: os.urandom(64),
    "encrypt": lambda k, p: _aes_xts_encrypt(k, p),
    "decrypt": lambda k, c: _aes_xts_decrypt(k, c),
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": False,
    "description": "AES-256-XTS (64B key = 2×AES-256, tweak 16B) — storage/disk encryption mode",
}


def _aes_xts_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """XTS requires data length multiple of 16 (except last partial sector handled by lib)."""
    if len(key) != 64:
        raise ValueError("AES-256-XTS requires a 64-byte key (two 32-byte AES keys).")
    tweak = os.urandom(16)
    # Pad to 16-byte boundary with PKCS7 for educational simplicity (real XTS uses ciphertext stealing)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(_alg.AES(key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    return tweak + encryptor.update(padded) + encryptor.finalize()


def _aes_xts_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 64:
        raise ValueError("AES-256-XTS requires a 64-byte key.")
    tweak, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(_alg.AES(key), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---- 17. Salsa20 (educational pure-Python stream cipher) ----
def _salsa20_quarterround(y0, y1, y2, y3):
    y1 ^= ((y0 + y3) & 0xFFFFFFFF) << 7 & 0xFFFFFFFF | ((y0 + y3) & 0xFFFFFFFF) >> 25
    y2 ^= ((y1 + y0) & 0xFFFFFFFF) << 9 & 0xFFFFFFFF | ((y1 + y0) & 0xFFFFFFFF) >> 23
    y3 ^= ((y2 + y1) & 0xFFFFFFFF) << 13 & 0xFFFFFFFF | ((y2 + y1) & 0xFFFFFFFF) >> 19
    y0 ^= ((y3 + y2) & 0xFFFFFFFF) << 18 & 0xFFFFFFFF | ((y3 + y2) & 0xFFFFFFFF) >> 14
    return y0 & 0xFFFFFFFF, y1 & 0xFFFFFFFF, y2 & 0xFFFFFFFF, y3 & 0xFFFFFFFF


def _salsa20_hash(state: list) -> bytes:
    """20-round Salsa20 core (sn, x0..x15)."""
    x = list(state)
    for _ in range(10):
        # column rounds
        x[0], x[4], x[8], x[12] = _salsa20_quarterround(x[0], x[4], x[8], x[12])
        x[5], x[9], x[13], x[1] = _salsa20_quarterround(x[5], x[9], x[13], x[1])
        x[10], x[14], x[2], x[6] = _salsa20_quarterround(x[10], x[14], x[2], x[6])
        x[15], x[3], x[7], x[11] = _salsa20_quarterround(x[15], x[3], x[7], x[11])
        # row rounds
        x[0], x[1], x[2], x[3] = _salsa20_quarterround(x[0], x[1], x[2], x[3])
        x[5], x[6], x[7], x[4] = _salsa20_quarterround(x[5], x[6], x[7], x[4])
        x[10], x[11], x[8], x[9] = _salsa20_quarterround(x[10], x[11], x[8], x[9])
        x[15], x[12], x[13], x[14] = _salsa20_quarterround(x[15], x[12], x[13], x[14])
    out = b""
    for i in range(16):
        out += ((x[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
    return out


def _salsa20_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Salsa20/20 keystream. key=32B, nonce=8B."""
    if len(key) != 32:
        raise ValueError("Salsa20 requires 32-byte key.")
    if len(nonce) != 8:
        raise ValueError("Salsa20 requires 8-byte nonce.")
    # constants "expand 32-byte k"
    c0, c1, c2, c3 = 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
    k = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    n = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 8, 4)]
    result = b""
    counter = 0
    while len(result) < length:
        state = [
            c0, k[0], k[1], k[2],
            k[3], c1, n[0], n[1],
            counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, c2, k[4],
            k[5], k[6], k[7], c3,
        ]
        result += _salsa20_hash(state)
        counter += 1
    return result[:length]


def _salsa20_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(8)
    ks = _salsa20_keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    return nonce + ct


def _salsa20_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce, ct = ciphertext[:8], ciphertext[8:]
    ks = _salsa20_keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


CIPHER_REGISTRY["Salsa20 (educational)"] = {
    "key_size": 32,
    "generate_key": lambda: os.urandom(32),
    "encrypt": _salsa20_encrypt,
    "decrypt": _salsa20_decrypt,
    "key_to_str": lambda k: k.hex(),
    "str_to_key": lambda s: bytes.fromhex(s.strip()),
    "ciphertext_format": "hex",
    "educational": True,
    "description": "Salsa20/20 pure-Python stream (nonce 8B) — educational reference implementation",
}


# ---- 18. RSA-2048-OAEP (asymmetric message encryption) ----
def _rsa_oaep_generate_key() -> bytes:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_oaep_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with RSA public key derived from private PEM. Max ~190 bytes for 2048-bit."""
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
    from cryptography.hazmat.primitives import serialization, hashes as hsh
    priv = serialization.load_pem_private_key(key, password=None)
    pub = priv.public_key()
    max_len = 190  # safe for SHA-256 OAEP on 2048-bit
    if len(plaintext) <= max_len:
        return pub.encrypt(
            plaintext,
            asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
        )
    # chunk for longer messages (educational; hybrid is preferred in production)
    chunks = []
    for i in range(0, len(plaintext), max_len):
        block = plaintext[i:i + max_len]
        enc = pub.encrypt(
            block,
            asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
        )
        chunks.append(len(enc).to_bytes(2, "big") + enc)
    return b"".join(chunks)


def _rsa_oaep_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
    from cryptography.hazmat.primitives import serialization, hashes as hsh
    priv = serialization.load_pem_private_key(key, password=None)
    # single block (256 bytes for 2048-bit)
    if len(ciphertext) == 256:
        return priv.decrypt(
            ciphertext,
            asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
        )
    # multi-chunk
    out = b""
    pos = 0
    while pos < len(ciphertext):
        wlen = int.from_bytes(ciphertext[pos:pos + 2], "big")
        pos += 2
        block = ciphertext[pos:pos + wlen]
        pos += wlen
        out += priv.decrypt(
            block,
            asym_pad.OAEP(mgf=asym_pad.MGF1(algorithm=hsh.SHA256()), algorithm=hsh.SHA256(), label=None),
        )
    return out


CIPHER_REGISTRY["RSA-2048-OAEP"] = {
    "key_size": None,
    "generate_key": _rsa_oaep_generate_key,
    "encrypt": _rsa_oaep_encrypt,
    "decrypt": _rsa_oaep_decrypt,
    "key_to_str": lambda k: k.decode() if isinstance(k, bytes) else str(k),
    "str_to_key": lambda s: s.encode() if isinstance(s, str) else s,
    "ciphertext_format": "hex",
    "educational": False,
    "description": "RSA-2048-OAEP-SHA256 asymmetric encryption (chunked for long messages)",
}


# ---------------------------------------------------------------------------
# Utility functions: padding visualization & IV/Nonce inspection
# ---------------------------------------------------------------------------

def visualize_pkcs7_padding(plaintext: bytes, block_size: int = 16) -> Dict:
    """
    Show PKCS#7 padding that would be applied before CBC/XTS-style block encryption.
    Returns dict with original, padded hex, pad length, and visual markers.
    """
    if block_size not in (8, 16):
        block_size = 16
    pad_len = block_size - (len(plaintext) % block_size)
    if pad_len == 0:
        pad_len = block_size
    pad_bytes = bytes([pad_len] * pad_len)
    padded = plaintext + pad_bytes
    return {
        "original_len": len(plaintext),
        "padded_len": len(padded),
        "pad_len": pad_len,
        "block_size": block_size,
        "original_hex": plaintext.hex(),
        "padded_hex": padded.hex(),
        "padding_hex": pad_bytes.hex(),
        "blocks": [
            padded[i:i + block_size].hex()
            for i in range(0, len(padded), block_size)
        ],
        "description": (
            f"PKCS#7: {pad_len} padding byte(s) of value 0x{pad_len:02x} "
            f"appended to reach multiple of {block_size}."
        ),
    }


# Known IV/nonce prefix sizes per mode (bytes prepended to ciphertext)
_IV_NONCE_LAYOUT: Dict[str, Dict] = {
    "Fernet (AES-128-CBC + HMAC)": {"iv_len": 0, "note": "Fernet embeds version+timestamp+IV internally (base64)"},
    "AES-256-GCM": {"iv_len": 12, "note": "12-byte nonce + ciphertext+tag"},
    "ChaCha20-Poly1305": {"iv_len": 12, "note": "12-byte nonce + ciphertext+tag"},
    "AES-256-CBC + HMAC-SHA256": {"iv_len": 16, "mac_len": 32, "note": "16B IV + CT + 32B HMAC"},
    "AES-128-GCM": {"iv_len": 12, "note": "12-byte nonce + ciphertext+tag"},
    "AES-128-CBC + HMAC-SHA256": {"iv_len": 16, "mac_len": 32, "note": "16B IV + CT + 32B HMAC"},
    "TripleDES (educational)": {"iv_len": 8, "note": "8-byte IV + CBC ciphertext"},
    "Blowfish (educational)": {"iv_len": 8, "note": "8-byte IV + CBC ciphertext"},
    "XOR + HMAC (educational)": {"iv_len": 0, "mac_len": 32, "note": "CT + 32B HMAC (no IV)"},
    "Vigenère (educational)": {"iv_len": 0, "note": "No IV (classical)"},
    "AES-256-CTR": {"iv_len": 16, "note": "16-byte nonce/counter block"},
    "AES-256-OFB": {"iv_len": 16, "note": "16-byte IV"},
    "AES-256-CFB": {"iv_len": 16, "note": "16-byte IV"},
    "ChaCha20 (stream)": {"iv_len": 16, "note": "16-byte nonce"},
    "Hybrid RSA-OAEP + AES-GCM": {"iv_len": 0, "note": "2B len + RSA-wrapped key + 12B nonce + CT"},
    "AES-256-XTS": {"iv_len": 16, "note": "16-byte tweak + XTS ciphertext"},
    "Salsa20 (educational)": {"iv_len": 8, "note": "8-byte nonce + keystream XOR"},
    "RSA-2048-OAEP": {"iv_len": 0, "note": "Pure RSA blocks (no IV)"},
}


def inspect_iv_nonce(mode_name: str, ciphertext: bytes) -> Dict:
    """
    Extract and describe IV/nonce (and MAC if present) from ciphertext for a given mode.
    Educational helper for understanding ciphertext structure.
    """
    layout = _IV_NONCE_LAYOUT.get(mode_name, {"iv_len": 0, "note": "Unknown layout"})
    iv_len = layout.get("iv_len", 0)
    mac_len = layout.get("mac_len", 0)
    result: Dict = {
        "mode": mode_name,
        "ciphertext_len": len(ciphertext),
        "note": layout.get("note", ""),
        "iv_nonce_hex": None,
        "iv_nonce_len": iv_len,
        "mac_hex": None,
        "mac_len": mac_len,
        "payload_len": max(0, len(ciphertext) - iv_len - mac_len),
        "warning": None,
    }
    if iv_len > 0 and len(ciphertext) >= iv_len:
        result["iv_nonce_hex"] = ciphertext[:iv_len].hex()
    if mac_len > 0 and len(ciphertext) >= mac_len:
        result["mac_hex"] = ciphertext[-mac_len:].hex()
    if iv_len > 0 and len(ciphertext) < iv_len:
        result["warning"] = f"Ciphertext shorter than expected IV/nonce ({iv_len} B)."
    # Nonce-reuse educational hint for AEAD modes
    if mode_name in ("AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"):
        result["security_note"] = (
            "NEVER reuse the same nonce with the same key in GCM/ChaCha20-Poly1305 — "
            "it destroys confidentiality and authenticity."
        )
    return result


# ---------------------------------------------------------------------------
# Public API — Cipher
# ---------------------------------------------------------------------------

def get_available_ciphers() -> list:
    return list(CIPHER_REGISTRY.keys())


def get_cipher_info(name: str) -> Optional[dict]:
    return CIPHER_REGISTRY.get(name)


def encrypt_with(mode_name: str, key: bytes, plaintext: bytes) -> bytes:
    info = CIPHER_REGISTRY.get(mode_name)
    if info is None:
        raise ValueError(f"Unknown cipher mode: {mode_name}")
    return info["encrypt"](key, plaintext)


def decrypt_with(mode_name: str, key: bytes, ciphertext: bytes) -> bytes:
    info = CIPHER_REGISTRY.get(mode_name)
    if info is None:
        raise ValueError(f"Unknown cipher mode: {mode_name}")
    return info["decrypt"](key, ciphertext)


# ---------------------------------------------------------------------------
# Key Derivation Registry
# ---------------------------------------------------------------------------

KEY_METHODS: list = []
"""Each entry: { "name": str, "needs_passphrase": bool, "derive": callable }"""


def _register_key_method(name: str, needs_passphrase: bool, needs_additional_input: bool,
                         derive_fn: Callable):
    KEY_METHODS.append({
        "name": name,
        "needs_passphrase": needs_passphrase,
        "needs_additional_input": needs_additional_input,
        "derive": derive_fn,
    })


def get_available_key_methods() -> list:
    return [m["name"] for m in KEY_METHODS]


def get_key_method_info(name: str) -> Optional[dict]:
    for m in KEY_METHODS:
        if m["name"] == name:
            return m
    return None


def derive_key(method_name: str, cipher_mode: str,
               passphrase: str = "", additional_input: str = "") -> Tuple[bytes, Optional[str]]:
    """Returns (key, optional_info_message)."""
    for m in KEY_METHODS:
        if m["name"] == method_name:
            return m["derive"](cipher_mode, passphrase, additional_input)
    raise ValueError(f"Unknown key method: {method_name}")


def _key_for_mode(raw: bytes, mode: str) -> bytes:
    """Convert raw derived bytes to the key format expected by mode."""
    info = CIPHER_REGISTRY.get(mode)
    if info is None:
        return raw[:32]
    # RSA-based modes need a full PEM keypair, not truncated KDF output
    if mode in ("Hybrid RSA-OAEP + AES-GCM", "RSA-2048-OAEP"):
        if mode == "RSA-2048-OAEP":
            return _rsa_oaep_generate_key()
        return _hybrid_generate_key()
    ks = info["key_size"]
    if ks is None:
        return raw[:32]
    if mode == "Fernet (AES-128-CBC + HMAC)":
        return base64.urlsafe_b64encode(raw[:ks])
    # Expand short material if needed (e.g. XTS 64B)
    if len(raw) < ks:
        expanded = raw
        while len(expanded) < ks:
            expanded += hashlib.sha256(expanded).digest()
        raw = expanded
    return raw[:ks]


# ---- KDF helpers ----

def _derive_pbkdf2_sha256(cipher_mode: str, passphrase: str, _extra: str) -> Tuple[bytes, str]:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt, iterations=PBKDF2_ITERATIONS)
    raw = kdf.derive(passphrase.encode())
    return _key_for_mode(raw, cipher_mode), f"Salt: {salt.hex()} ({PBKDF2_ITERATIONS} iter)"


def _derive_pbkdf2_sha512(cipher_mode: str, passphrase: str, _extra: str) -> Tuple[bytes, str]:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=PBKDF2_ITERATIONS)
    raw = kdf.derive(passphrase.encode())
    return _key_for_mode(raw, cipher_mode), f"Salt: {salt.hex()} ({PBKDF2_ITERATIONS} iter, SHA-512)"


def _derive_scrypt(cipher_mode: str, passphrase: str, _extra: str) -> Tuple[bytes, str]:
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=64, n=2 ** 17, r=8, p=1)
    raw = kdf.derive(passphrase.encode())
    return _key_for_mode(raw, cipher_mode), f"Salt: {salt.hex()} (N=2^17, r=8, p=1)"


def _derive_hkdf(cipher_mode: str, _passphrase: str, ikm: str) -> Tuple[bytes, str]:
    if not ikm.strip():
        raise ValueError("Input Key Material cannot be empty.")
    raw_ikm = ikm.strip().encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'HKDF Key Derivation')
    raw = hkdf.derive(raw_ikm)
    return _key_for_mode(raw, cipher_mode), "HKDF-SHA256 derived from raw IKM"


def _derive_ecdh(cipher_mode: str, _passphrase: str, peer_pub_b64: str) -> Tuple[bytes, str]:
    from cryptography.hazmat.primitives.asymmetric import x25519
    peer_raw = base64.b64decode(peer_pub_b64.strip())
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_raw)
    # Use an ephemeral key for the exchange
    priv = x25519.X25519PrivateKey.generate()
    shared_secret = priv.exchange(peer_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'ECDH Key Agreement')
    raw = hkdf.derive(shared_secret)
    return _key_for_mode(raw, cipher_mode), "ECDH X25519 shared key derived"


def _derive_argon2id(cipher_mode: str, passphrase: str, extra: str) -> Tuple[bytes, str]:
    """Argon2id with optional parameter override via extra: 't=3,m=65536,p=4'."""
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise ImportError("Argon2id requires 'argon2-cffi'. Install with: pip install argon2-cffi")
    time_cost, memory_cost, parallelism = 2, 19456, 1
    if extra and extra.strip():
        for part in extra.replace(" ", "").split(","):
            if part.startswith("t="):
                time_cost = max(1, int(part[2:]))
            elif part.startswith("m="):
                memory_cost = max(8, int(part[2:]))
            elif part.startswith("p="):
                parallelism = max(1, int(part[2:]))
    salt = os.urandom(16)
    raw = hash_secret_raw(
        passphrase.encode(),
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=64,
        type=Type.ID,
    )
    return (
        _key_for_mode(raw, cipher_mode),
        f"Salt: {salt.hex()} (Argon2id t={time_cost}, m={memory_cost} KiB, p={parallelism})",
    )


def estimate_password_strength(password: str) -> Dict:
    """Simple entropy-based password strength estimate (bits + label)."""
    if not password:
        return {"entropy_bits": 0.0, "label": "Empty", "score": 0}
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32
    charset = max(charset, 1)
    entropy = len(password) * math.log2(charset)
    if entropy < 28:
        label, score = "Very Weak", 1
    elif entropy < 36:
        label, score = "Weak", 2
    elif entropy < 60:
        label, score = "Moderate", 3
    elif entropy < 128:
        label, score = "Strong", 4
    else:
        label, score = "Very Strong", 5
    return {"entropy_bits": round(entropy, 1), "label": label, "score": score}


def _derive_hmac_sha256(cipher_mode: str, _passphrase: str, seed: str) -> Tuple[bytes, str]:
    if not seed.strip():
        raise ValueError("Master seed cannot be empty.")
    raw_seed = seed.strip().encode()
    raw = hashlib.sha256(raw_seed).digest()
    # Expand to 64 bytes using HMAC in counter mode
    result = b""
    for i in range(4):
        h = hmac_module.new(raw, i.to_bytes(4, "big"), hashlib.sha256)
        result += h.digest()
    return _key_for_mode(result[:64], cipher_mode), "HMAC-SHA256 key expansion from seed"


def _derive_sha256_direct(cipher_mode: str, _passphrase: str, text: str) -> Tuple[bytes, str]:
    if not text.strip():
        raise ValueError("Input text cannot be empty.")
    raw = hashlib.sha256(text.strip().encode()).digest()
    # repeat to get 64 bytes
    result = raw + hashlib.sha256(raw).digest()
    return _key_for_mode(result[:64], cipher_mode), "Direct SHA-256 hash (no stretching — educational)"


def _derive_layered_kdf(cipher_mode: str, passphrase: str, _extra: str) -> Tuple[bytes, str]:
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    # Layer 1: PBKDF2
    k1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt1, iterations=100000)
    intermediate = k1.derive(passphrase.encode())
    # Layer 2: scrypt on the intermediate key
    kdf2 = Scrypt(salt=salt2, length=64, n=2 ** 15, r=8, p=1)
    raw = kdf2.derive(intermediate + passphrase.encode())
    return _key_for_mode(raw, cipher_mode), f"Salt1: {salt1.hex()}, Salt2: {salt2.hex()} (PBKDF2(100k) + scrypt(N=2^15))"


# ---- Register all key methods ----
_register_key_method("Random Key", needs_passphrase=False, needs_additional_input=False,
                     derive_fn=lambda mode, pp, extra: (
                         CIPHER_REGISTRY[mode]["generate_key"](), "Random key generated"))

_register_key_method("PBKDF2 (SHA-256) Passphrase", needs_passphrase=True, needs_additional_input=False,
                     derive_fn=_derive_pbkdf2_sha256)

_register_key_method("PBKDF2 (SHA-512) Passphrase", needs_passphrase=True, needs_additional_input=False,
                     derive_fn=_derive_pbkdf2_sha512)

_register_key_method("scrypt Passphrase", needs_passphrase=True, needs_additional_input=False,
                     derive_fn=_derive_scrypt)

_register_key_method("HKDF from Input Key Material", needs_passphrase=False, needs_additional_input=True,
                     derive_fn=_derive_hkdf)

_register_key_method("ECDH X25519 Key Agreement", needs_passphrase=False, needs_additional_input=True,
                     derive_fn=_derive_ecdh)

_register_key_method("Argon2id Passphrase", needs_passphrase=True, needs_additional_input=False,
                     derive_fn=_derive_argon2id)  # extra unused; OWASP-like defaults (t=2, m=19456, p=1)

_register_key_method("HMAC-SHA256 from Master Seed", needs_passphrase=False, needs_additional_input=True,
                     derive_fn=_derive_hmac_sha256)

_register_key_method("SHA-256 Direct Hash", needs_passphrase=False, needs_additional_input=True,
                     derive_fn=_derive_sha256_direct)

_register_key_method("Layered KDF (PBKDF2 + scrypt)", needs_passphrase=True, needs_additional_input=False,
                     derive_fn=_derive_layered_kdf)


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

class AdvancedCryptoEngine:
    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes = None,
                                   iterations: int = PBKDF2_ITERATIONS) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        derived_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return derived_key, salt

    @staticmethod
    def generate_ecdh_keypair():
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def compute_ecdh_shared_key(private_key, peer_public_key) -> bytes:
        shared_secret = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                           info=b'ECDH Fernet Key Agreement').derive(shared_secret)
        return base64.urlsafe_b64encode(derived_key)

    @staticmethod
    def validate_fernet_key(key_str: str) -> bool:
        try:
            Fernet(key_str.encode())
            return True
        except Exception:
            return False

    @staticmethod
    def encrypt_fernet(key: bytes, plaintext: str) -> bytes:
        return Fernet(key).encrypt(plaintext.encode())

    @staticmethod
    def decrypt_fernet(key_str: str, ciphertext: str) -> str:
        return Fernet(key_str.encode().strip()).decrypt(ciphertext.encode().strip()).decode("utf-8")

    @staticmethod
    def generate_license_code(ciphertext: bytes) -> str:
        import re
        b64 = base64.b64encode(ciphertext).decode().replace("=", "").upper()
        clean_b64 = re.sub(r"[^A-Z0-9]", "X", b64)
        return "-".join([clean_b64[i:i + 5] for i in range(0, min(40, len(clean_b64)), 5)])


class AESGCMCrypto:
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def key_to_hex(key: bytes) -> str:
        return key.hex()

    @staticmethod
    def key_from_hex(hex_str: str) -> bytes:
        return bytes.fromhex(hex_str.strip())

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ct

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(ciphertext[:12], ciphertext[12:], associated_data)
