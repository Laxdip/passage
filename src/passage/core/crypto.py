"""Master-password encryption for Passage.

Derives an AES-256 key from the master password using PBKDF2-HMAC-SHA256.
The SQLite database bytes are stored encrypted on disk; we decrypt to a temp
file only for the duration of a session (held in memory as a bytes buffer when
feasible, written to a NamedTemporaryFile otherwise).
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


_SALT_FILE_SUFFIX = ".salt"
_VERIFY_FILE_SUFFIX = ".verify"
# A fixed known plaintext we encrypt with the derived key so we can verify
# the master password is correct before trying to decrypt the whole DB.
_VERIFY_PLAINTEXT = b"passage-verify-v1"


def _salt_path(db_path: Path) -> Path:
    return db_path.with_suffix(_SALT_FILE_SUFFIX)


def _verify_path(db_path: Path) -> Path:
    return db_path.with_suffix(_VERIFY_FILE_SUFFIX)


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte key and return it base64-url encoded (Fernet format)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(raw)


def setup_master_password(password: str, db_path: Path, iterations: int = 310_000) -> None:
    """Initialise salt + verify token for a brand-new vault."""
    salt = secrets.token_bytes(32)
    _salt_path(db_path).write_bytes(salt)

    key = _derive_key(password, salt, iterations)
    fernet = Fernet(key)
    token = fernet.encrypt(_VERIFY_PLAINTEXT)
    _verify_path(db_path).write_bytes(token)


def verify_master_password(password: str, db_path: Path, iterations: int = 310_000) -> bool:
    """Return True if *password* is the correct master password."""
    salt_path = _salt_path(db_path)
    verify_path = _verify_path(db_path)
    if not salt_path.exists() or not verify_path.exists():
        return False

    salt = salt_path.read_bytes()
    key = _derive_key(password, salt, iterations)
    fernet = Fernet(key)
    try:
        fernet.decrypt(verify_path.read_bytes())
        return True
    except InvalidToken:
        return False


def encrypt_db(plain_bytes: bytes, password: str, db_path: Path, iterations: int = 310_000) -> None:
    """Encrypt *plain_bytes* and write to *db_path*."""
    salt = _salt_path(db_path).read_bytes()
    key = _derive_key(password, salt, iterations)
    fernet = Fernet(key)
    db_path.write_bytes(fernet.encrypt(plain_bytes))


def decrypt_db(password: str, db_path: Path, iterations: int = 310_000) -> bytes:
    """Decrypt *db_path* and return raw SQLite bytes."""
    salt = _salt_path(db_path).read_bytes()
    key = _derive_key(password, salt, iterations)
    fernet = Fernet(key)
    try:
        return fernet.decrypt(db_path.read_bytes())
    except InvalidToken as exc:
        raise ValueError("Invalid master password or corrupted database.") from exc


def hash_password_bcrypt(password: str) -> str:
    """Return bcrypt hash string for change-detection storage."""
    import bcrypt  # local import to keep startup fast
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_bcrypt(password: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(password.encode(), hashed.encode())


def sha1_hex(password: str) -> str:
    """SHA-1 hex digest – used for HIBP k-anonymity prefix."""
    return hashlib.sha1(password.encode()).hexdigest().upper()


def fuzzy_hash(password: str) -> int:
    """SimHash-style 64-bit fingerprint for reuse detection (no plaintext stored)."""
    # Character-level shingle hashing → 64-bit vector
    v = [0] * 64
    data = password.encode()
    for i in range(len(data)):
        shingle = data[i : i + 3]
        h = int(hashlib.sha256(shingle).hexdigest(), 16)
        for bit in range(64):
            if h & (1 << bit):
                v[bit] += 1
            else:
                v[bit] -= 1
    result = 0
    for bit in range(64):
        if v[bit] > 0:
            result |= 1 << bit
    # Convert to signed 64-bit so SQLite INTEGER can store it
    if result >= (1 << 63):
        result -= (1 << 64)
    return result


def fuzzy_similarity(h1: int, h2: int) -> float:
    """Hamming-distance-based similarity in [0, 1]."""
    # Mask to 64 bits to handle negative (signed) stored values
    xor = (h1 & 0xFFFFFFFFFFFFFFFF) ^ (h2 & 0xFFFFFFFFFFFFFFFF)
    differing_bits = bin(xor).count("1")
    return 1.0 - differing_bits / 64.0


# ---------------------------------------------------------------------------
# Bcrypt shim – falls back to PBKDF2 if bcrypt package unavailable
# ---------------------------------------------------------------------------

def _bcrypt_available() -> bool:
    try:
        import bcrypt  # noqa: F401
        return True
    except ImportError:
        return False


def hash_password_bcrypt(password: str) -> str:  # type: ignore[misc]  # re-define
    """Return a hash for change-detection storage.

    Uses bcrypt when available, otherwise falls back to PBKDF2-HMAC-SHA256
    with a random salt (stored as hex prefix).
    """
    if _bcrypt_available():
        import bcrypt as _bcrypt
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()
    # Fallback: "$pbkdf2$<salt_hex>$<hash_hex>"
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"$pbkdf2${salt.hex()}${dk.hex()}"


def verify_bcrypt(password: str, hashed: str) -> bool:  # type: ignore[misc]
    if hashed.startswith("$pbkdf2$"):
        _, _, salt_hex, hash_hex = hashed.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return dk.hex() == hash_hex
    if _bcrypt_available():
        import bcrypt as _bcrypt
        return _bcrypt.checkpw(password.encode(), hashed.encode())
    return False
