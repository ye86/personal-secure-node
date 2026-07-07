import os
import uuid
from pathlib import Path

from .crypto import VaultCipher
from .errors import IntegrityError


class BlobStore:
    def __init__(self, root: Path, cipher: VaultCipher):
        self.root = root
        self.cipher = cipher

    def path_for(self, chunk_id: str) -> Path:
        return self.root / chunk_id[:2] / chunk_id[2:4] / chunk_id

    def exists(self, chunk_id: str) -> bool:
        return self.path_for(chunk_id).is_file()

    def disk_usage(self) -> int:
        if not self.root.exists():
            return 0
        return sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())

    def put(self, chunk_id: str, plaintext: bytes) -> tuple[int, bool]:
        target = self.path_for(chunk_id)
        if target.exists():
            return target.stat().st_size, False
        target.parent.mkdir(parents=True, exist_ok=True)
        blob = self.cipher.encrypt_chunk(chunk_id, plaintext)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            if target.exists():
                temporary.unlink(missing_ok=True)
                return target.stat().st_size, False
            os.replace(temporary, target)
            return len(blob), True
        finally:
            temporary.unlink(missing_ok=True)

    def get(self, chunk_id: str) -> bytes:
        path = self.path_for(chunk_id)
        if not path.exists():
            raise IntegrityError(f"missing chunk: {chunk_id}")
        return self.cipher.decrypt_chunk(chunk_id, path.read_bytes())

    def delete(self, chunk_id: str) -> bool:
        path = self.path_for(chunk_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    def stored_chunk_ids(self) -> set[str]:
        if not self.root.exists():
            return set()
        return {
            path.name
            for path in self.root.rglob("*")
            if path.is_file() and len(path.name) == 64 and not path.name.startswith(".")
        }
