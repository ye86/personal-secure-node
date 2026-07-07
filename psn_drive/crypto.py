import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError, VaultNotInitialized

MASTER_KEY_SIZE = 32
NONCE_SIZE = 12
BLOB_MAGIC = b"PSNB1"
BLOB_OVERHEAD = len(BLOB_MAGIC) + NONCE_SIZE + 16


def create_master_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"master key already exists: {path}")
    path.write_bytes(os.urandom(MASTER_KEY_SIZE))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_master_key(path: Path) -> bytes:
    if not path.exists():
        raise VaultNotInitialized("vault is not initialized")
    key = path.read_bytes()
    if len(key) != MASTER_KEY_SIZE:
        raise IntegrityError("invalid vault master key")
    return key


def derive_key(master_key: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"psn-drive/v1/" + purpose,
    ).derive(master_key)


class VaultCipher:
    def __init__(self, master_key: bytes):
        self._id_key = derive_key(master_key, b"chunk-id")
        self._encryption_key = derive_key(master_key, b"chunk-encryption")
        self._aead = ChaCha20Poly1305(self._encryption_key)

    def chunk_id(self, plaintext: bytes) -> str:
        return hmac.new(self._id_key, plaintext, hashlib.sha256).hexdigest()

    def encrypt_chunk(self, chunk_id: str, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_SIZE)
        aad = chunk_id.encode("ascii")
        return BLOB_MAGIC + nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt_chunk(self, chunk_id: str, blob: bytes) -> bytes:
        if len(blob) < len(BLOB_MAGIC) + NONCE_SIZE + 16 or not blob.startswith(BLOB_MAGIC):
            raise IntegrityError(f"invalid encrypted blob: {chunk_id}")
        nonce_start = len(BLOB_MAGIC)
        nonce = blob[nonce_start : nonce_start + NONCE_SIZE]
        ciphertext = blob[nonce_start + NONCE_SIZE :]
        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, chunk_id.encode("ascii"))
        except Exception as exc:
            raise IntegrityError(f"cannot decrypt chunk: {chunk_id}") from exc
        if not hmac.compare_digest(self.chunk_id(plaintext), chunk_id):
            raise IntegrityError(f"chunk identifier mismatch: {chunk_id}")
        return plaintext
