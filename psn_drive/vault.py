import hashlib
import json
import os
import posixpath
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from .crypto import BLOB_OVERHEAD, VaultCipher, create_master_key, load_master_key
from .database import backup_database, connect, initialize, restore_database
from .disaster_backup import create_disaster_backup, list_disaster_backups, restore_disaster_backup
from .errors import (
    FileNotFoundInVault,
    IntegrityError,
    InvalidVirtualPath,
    QuotaExceeded,
    RestoreConflict,
    UploadConflict,
    UploadSessionExpired,
    UploadSessionNotFound,
    VaultNotInitialized,
)
from .storage import BlobStore

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_SHARE_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_SHARE_TTL_SECONDS = 365 * 24 * 60 * 60
ENTITY_TYPES = {"person", "organization", "user", "agent", "unknown"}
ARTIFACT_KINDS = {"plugin", "skill", "app", "work"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_virtual_path(value: str) -> str:
    value = value.replace("\\", "/").strip()
    normalized = posixpath.normpath(value).lstrip("/")
    path = PurePosixPath(normalized)
    if not value or normalized in ("", ".") or ".." in path.parts:
        raise InvalidVirtualPath(f"invalid vault path: {value!r}")
    return path.as_posix()


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ImportResult:
    file_id: str
    version_id: str
    virtual_path: str
    size: int
    chunks: int
    new_chunks: int
    unchanged: bool


class Vault:
    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()
        self.control = self.root / ".psn"
        self.key_path = self.control / "master.key"
        self.database_path = self.control / "metadata.sqlite3"
        if not self.key_path.exists() or not self.database_path.exists():
            raise VaultNotInitialized(f"not a PSN Drive vault: {self.root}")
        initialize(self.database_path)
        cipher = VaultCipher(load_master_key(self.key_path))
        self.blobs = BlobStore(self.control / "blobs", cipher)

    @classmethod
    def create(cls, root: Path | str) -> "Vault":
        root = Path(root).resolve()
        control = root / ".psn"
        if control.exists():
            raise FileExistsError(f"vault already exists: {root}")
        control.mkdir(parents=True)
        try:
            create_master_key(control / "master.key")
            initialize(control / "metadata.sqlite3")
            (control / "blobs").mkdir()
        except Exception:
            # Keep partial state visible for diagnosis; a second init must not overwrite keys.
            raise
        return cls(root)

    def _connect(self) -> sqlite3.Connection:
        return connect(self.database_path)

    @staticmethod
    def _ensure_directories(conn: sqlite3.Connection, virtual_path: str, now: str) -> None:
        parts = PurePosixPath(virtual_path).parts[:-1]
        current = []
        for part in parts:
            current.append(part)
            conn.execute(
                "INSERT OR IGNORE INTO directories(virtual_path, created_at) VALUES (?, ?)",
                ("/".join(current), now),
            )

    def import_file(
        self, source: Path | str, virtual_path: str | None = None, chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> ImportResult:
        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(source)
        if chunk_size <= 0:
            raise ValueError("chunk size must be positive")
        virtual_path = normalize_virtual_path(virtual_path or source.name)

        quota = self.get_quota()
        physical_usage = self.blobs.disk_usage()

        content_hash = hashlib.sha256()
        chunk_records: list[tuple[str, int, int, bool]] = []
        total_size = 0
        with source.open("rb") as handle:
            while True:
                plaintext = handle.read(chunk_size)
                if not plaintext:
                    break
                total_size += len(plaintext)
                content_hash.update(plaintext)
                chunk_id = self.blobs.cipher.chunk_id(plaintext)
                if not self.blobs.exists(chunk_id) and quota is not None:
                    estimated_size = len(plaintext) + BLOB_OVERHEAD
                    if physical_usage + estimated_size > quota:
                        raise QuotaExceeded(
                            f"vault quota exceeded: need {estimated_size} additional bytes, "
                            f"{max(quota - physical_usage, 0)} available"
                        )
                stored_size, created = self.blobs.put(chunk_id, plaintext)
                if created:
                    physical_usage += stored_size
                chunk_records.append((chunk_id, len(plaintext), stored_size, created))

        digest = content_hash.hexdigest()
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            file_row = conn.execute(
                "SELECT id, current_version_id FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                (virtual_path,),
            ).fetchone()
            if file_row is not None and file_row["current_version_id"]:
                current = conn.execute(
                    "SELECT id, size, content_hash FROM versions WHERE id = ?",
                    (file_row["current_version_id"],),
                ).fetchone()
                if current and current["size"] == total_size and current["content_hash"] == digest:
                    conn.rollback()
                    return ImportResult(
                        file_row["id"], current["id"], virtual_path, total_size,
                        len(chunk_records), 0, True,
                    )

            file_id = file_row["id"] if file_row else uuid.uuid4().hex
            version_id = uuid.uuid4().hex
            if file_row is None:
                self._ensure_directories(conn, virtual_path, now)
                conn.execute(
                    "INSERT INTO files(id, virtual_path, created_at) VALUES (?, ?, ?)",
                    (file_id, virtual_path, now),
                )
            conn.execute(
                "INSERT INTO versions(id, file_id, size, content_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (version_id, file_id, total_size, digest, now),
            )
            for ordinal, (chunk_id, plain_size, stored_size, _) in enumerate(chunk_records):
                row = conn.execute("SELECT plain_size FROM chunks WHERE id = ?", (chunk_id,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO chunks(id, ref_count, plain_size, stored_size, created_at) VALUES (?, 1, ?, ?, ?)",
                        (chunk_id, plain_size, stored_size, now),
                    )
                else:
                    if row["plain_size"] != plain_size:
                        raise IntegrityError("chunk metadata collision")
                    conn.execute("UPDATE chunks SET ref_count = ref_count + 1 WHERE id = ?", (chunk_id,))
                conn.execute(
                    "INSERT INTO version_chunks(version_id, ordinal, chunk_id, plain_size) VALUES (?, ?, ?, ?)",
                    (version_id, ordinal, chunk_id, plain_size),
                )
            conn.execute("UPDATE files SET current_version_id = ? WHERE id = ?", (version_id, file_id))
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.version.created', ?, ?, ?)",
                (file_id, version_id, now),
            )
            conn.commit()
            return ImportResult(
                file_id, version_id, virtual_path, total_size, len(chunk_records),
                sum(1 for record in chunk_records if record[3]), False,
            )
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_files(self, include_deleted: bool = False) -> list[dict]:
        where = "" if include_deleted else "WHERE f.deleted_at IS NULL"
        conn = self._connect()
        try:
            rows = conn.execute(
                f"""
                SELECT f.id, f.virtual_path, f.deleted_at, v.id AS version_id,
                       v.size, v.content_hash, v.created_at
                FROM files f
                LEFT JOIN versions v ON v.id = f.current_version_id
                {where}
                ORDER BY f.virtual_path
                """
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def browse(self, prefix: str = "") -> dict:
        prefix = prefix.replace("\\", "/").strip("/")
        if prefix:
            prefix = normalize_virtual_path(prefix)
        base = f"{prefix}/" if prefix else ""
        directories: dict[str, dict] = {}
        files = []
        conn = self._connect()
        try:
            explicit_directories = [row[0] for row in conn.execute("SELECT virtual_path FROM directories")]
        finally:
            conn.close()
        for directory_path in explicit_directories:
            if not directory_path.startswith(base):
                continue
            remainder = directory_path[len(base):]
            if remainder and "/" not in remainder:
                directories[remainder] = {"name": remainder, "path": directory_path}
        for item in self.list_files():
            path = item["virtual_path"]
            if not path.startswith(base):
                continue
            remainder = path[len(base):]
            if "/" in remainder:
                name = remainder.split("/", 1)[0]
                directories[name] = {"name": name, "path": f"{base}{name}"}
            else:
                files.append(item)
        parent = prefix.rsplit("/", 1)[0] if "/" in prefix else ""
        return {
            "prefix": prefix,
            "parent": parent,
            "directories": sorted(directories.values(), key=lambda item: item["name"].lower()),
            "files": sorted(files, key=lambda item: item["virtual_path"].lower()),
        }

    def create_directory(self, virtual_path: str) -> dict:
        virtual_path = normalize_virtual_path(virtual_path)
        now = utc_now()
        conn = self._connect()
        try:
            parts = PurePosixPath(virtual_path).parts
            current = []
            for part in parts:
                current.append(part)
                conn.execute(
                    "INSERT OR IGNORE INTO directories(virtual_path, created_at) VALUES (?, ?)",
                    ("/".join(current), now),
                )
            conn.commit()
            return {"virtual_path": virtual_path, "created": True}
        finally:
            conn.close()

    def list_deleted_files(self) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT f.id, f.virtual_path, f.deleted_at, v.id AS version_id,
                       v.size, v.content_hash, v.created_at
                FROM files f LEFT JOIN versions v ON v.id = f.current_version_id
                WHERE f.deleted_at IS NOT NULL ORDER BY f.deleted_at DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def move_file(self, source_path: str, destination_path: str) -> dict:
        source_path = normalize_virtual_path(source_path)
        destination_path = normalize_virtual_path(destination_path)
        if source_path == destination_path:
            return {"source": source_path, "destination": destination_path, "moved": False}
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            source = conn.execute(
                "SELECT id, current_version_id FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                (source_path,),
            ).fetchone()
            if source is None:
                raise FileNotFoundInVault(source_path)
            conflict = conn.execute(
                "SELECT 1 FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                (destination_path,),
            ).fetchone()
            if conflict is not None:
                raise RestoreConflict(f"destination already exists: {destination_path}")
            self._ensure_directories(conn, destination_path, now)
            conn.execute("UPDATE files SET virtual_path = ? WHERE id = ?", (destination_path, source["id"]))
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.moved', ?, ?, ?)",
                (source["id"], source["current_version_id"], now),
            )
            conn.commit()
            return {"source": source_path, "destination": destination_path, "moved": True}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def move_files(self, moves: list[dict]) -> dict:
        if not moves or len(moves) > 100:
            raise ValueError("batch move requires 1 to 100 items")
        normalized = [
            (normalize_virtual_path(item["source"]), normalize_virtual_path(item["destination"]))
            for item in moves
        ]
        sources = [item[0] for item in normalized]
        destinations = [item[1] for item in normalized]
        if len(set(sources)) != len(sources) or len(set(destinations)) != len(destinations):
            raise ValueError("batch move contains duplicate source or destination")
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = {}
            for source in sources:
                row = conn.execute(
                    "SELECT id, current_version_id FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                    (source,),
                ).fetchone()
                if row is None:
                    raise FileNotFoundInVault(source)
                rows[source] = row
            placeholders = ",".join("?" for _ in destinations)
            conflicts = conn.execute(
                f"SELECT virtual_path FROM files WHERE deleted_at IS NULL AND virtual_path IN ({placeholders})",
                destinations,
            ).fetchall()
            for conflict in conflicts:
                if conflict["virtual_path"] not in sources:
                    raise RestoreConflict(f"destination already exists: {conflict['virtual_path']}")
            temporary_paths = {}
            for source in sources:
                temporary = f".psn-batch-{uuid.uuid4().hex}"
                temporary_paths[source] = temporary
                conn.execute("UPDATE files SET virtual_path = ? WHERE id = ?", (temporary, rows[source]["id"]))
            for source, destination in normalized:
                self._ensure_directories(conn, destination, now)
                conn.execute("UPDATE files SET virtual_path = ? WHERE id = ?", (destination, rows[source]["id"]))
                conn.execute(
                    "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.moved', ?, ?, ?)",
                    (rows[source]["id"], rows[source]["current_version_id"], now),
                )
            conn.commit()
            return {"moved": len(normalized), "items": [{"source": s, "destination": d} for s, d in normalized]}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def backup_metadata(self, label: str = "manual") -> dict:
        return backup_database(self.database_path, self.control / "backups", label)

    def list_metadata_backups(self) -> list[dict]:
        backup_dir = self.control / "backups"
        if not backup_dir.exists():
            return []
        results = []
        import json
        for manifest_path in sorted(backup_dir.glob("metadata-*.json"), reverse=True):
            try:
                value = json.loads(manifest_path.read_text(encoding="utf-8"))
                value["path"] = str(backup_dir / value["database"])
                results.append(value)
            except (OSError, ValueError, KeyError):
                continue
        return results

    def restore_metadata(self, backup_path: Path | str) -> dict:
        return restore_database(self.database_path, Path(backup_path))

    def backup_disaster(self, destination: Path | str | None = None, label: str = "manual") -> dict:
        return create_disaster_backup(self, destination, label)

    def list_disaster_backups(self) -> list[dict]:
        return list_disaster_backups(self.control)

    @classmethod
    def restore_disaster(cls, archive: Path | str, root: Path | str, force: bool = False) -> dict:
        result = restore_disaster_backup(archive, root, force)
        vault = cls(root)
        result["verify"] = vault.verify()
        result["status"] = vault.status()
        return result

    def list_versions(self, virtual_path: str) -> list[dict]:
        virtual_path = normalize_virtual_path(virtual_path)
        conn = self._connect()
        try:
            file_row = conn.execute(
                "SELECT id, current_version_id, deleted_at FROM files WHERE virtual_path = ? ORDER BY created_at DESC LIMIT 1",
                (virtual_path,),
            ).fetchone()
            if file_row is None:
                raise FileNotFoundInVault(virtual_path)
            rows = conn.execute(
                """
                SELECT id, size, content_hash, created_at,
                       CASE WHEN id = ? THEN 1 ELSE 0 END AS is_current
                FROM versions WHERE file_id = ? ORDER BY created_at DESC
                """,
                (file_row["current_version_id"], file_row["id"]),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def export_file(
        self, virtual_path: str, destination: Path | str, version_id: str | None = None
    ) -> dict:
        virtual_path = normalize_virtual_path(virtual_path)
        destination = Path(destination)
        conn = self._connect()
        try:
            if version_id is None:
                row = conn.execute(
                    """
                    SELECT f.id AS file_id, v.id AS version_id, v.size, v.content_hash
                    FROM files f JOIN versions v ON v.id = f.current_version_id
                    WHERE f.virtual_path = ? AND f.deleted_at IS NULL
                    """,
                    (virtual_path,),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT f.id AS file_id, v.id AS version_id, v.size, v.content_hash
                    FROM files f JOIN versions v ON v.file_id = f.id
                    WHERE f.virtual_path = ? AND v.id = ?
                    ORDER BY f.created_at DESC LIMIT 1
                    """,
                    (virtual_path, version_id),
                ).fetchone()
            if row is None:
                raise FileNotFoundInVault(virtual_path)
            chunks = conn.execute(
                "SELECT chunk_id, plain_size FROM version_chunks WHERE version_id = ? ORDER BY ordinal",
                (row["version_id"],),
            ).fetchall()
        finally:
            conn.close()

        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        digest = hashlib.sha256()
        size = 0
        try:
            with temporary.open("xb") as handle:
                for chunk in chunks:
                    plaintext = self.blobs.get(chunk["chunk_id"])
                    if len(plaintext) != chunk["plain_size"]:
                        raise IntegrityError("chunk size mismatch")
                    handle.write(plaintext)
                    digest.update(plaintext)
                    size += len(plaintext)
                handle.flush()
                os.fsync(handle.fileno())
            if size != row["size"] or digest.hexdigest() != row["content_hash"]:
                raise IntegrityError("exported file integrity mismatch")
            os.replace(temporary, destination)
            return dict(row)
        finally:
            temporary.unlink(missing_ok=True)

    def download_manifest(self, virtual_path: str, version_id: str | None = None) -> tuple[dict, list[dict]]:
        virtual_path = normalize_virtual_path(virtual_path)
        conn = self._connect()
        try:
            if version_id is None:
                row = conn.execute(
                    """
                    SELECT f.id AS file_id, f.virtual_path, v.id AS version_id, v.size, v.content_hash
                    FROM files f JOIN versions v ON v.id = f.current_version_id
                    WHERE f.virtual_path = ? AND f.deleted_at IS NULL
                    """,
                    (virtual_path,),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT f.id AS file_id, f.virtual_path, v.id AS version_id, v.size, v.content_hash
                    FROM files f JOIN versions v ON v.file_id = f.id
                    WHERE f.virtual_path = ? AND v.id = ? ORDER BY f.created_at DESC LIMIT 1
                    """,
                    (virtual_path, version_id),
                ).fetchone()
            if row is None:
                raise FileNotFoundInVault(virtual_path)
            chunks = conn.execute(
                "SELECT ordinal, chunk_id, plain_size FROM version_chunks WHERE version_id = ? ORDER BY ordinal",
                (row["version_id"],),
            ).fetchall()
            return dict(row), [dict(chunk) for chunk in chunks]
        finally:
            conn.close()

    def create_share_link(
        self,
        virtual_path: str,
        ttl_seconds: int = DEFAULT_SHARE_TTL_SECONDS,
        max_downloads: int | None = None,
    ) -> dict:
        virtual_path = normalize_virtual_path(virtual_path)
        ttl_seconds = int(ttl_seconds)
        if ttl_seconds < 60 or ttl_seconds > MAX_SHARE_TTL_SECONDS:
            raise ValueError("share link TTL must be between 60 seconds and 365 days")
        if max_downloads is not None:
            max_downloads = int(max_downloads)
            if max_downloads <= 0:
                raise ValueError("share link max_downloads must be positive")
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        expires = (now_dt + timedelta(seconds=ttl_seconds)).isoformat()
        raw_token = secrets.token_urlsafe(32)
        share_id = uuid.uuid4().hex
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            file_row = conn.execute(
                """
                SELECT f.id AS file_id, f.virtual_path, v.id AS version_id, v.size, v.content_hash
                FROM files f JOIN versions v ON v.id = f.current_version_id
                WHERE f.virtual_path = ? AND f.deleted_at IS NULL
                """,
                (virtual_path,),
            ).fetchone()
            if file_row is None:
                raise FileNotFoundInVault(virtual_path)
            conn.execute(
                """
                INSERT INTO share_links(
                    id, token_hash, file_id, version_id, virtual_path, created_at,
                    expires_at, max_downloads, download_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    share_id,
                    token_hash(raw_token),
                    file_row["file_id"],
                    file_row["version_id"],
                    virtual_path,
                    now,
                    expires,
                    max_downloads,
                ),
            )
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('share.created', ?, ?, ?)",
                (file_row["file_id"], file_row["version_id"], now),
            )
            conn.commit()
            return {
                "id": share_id,
                "token": raw_token,
                "url_path": f"/s/{raw_token}",
                "virtual_path": virtual_path,
                "version_id": file_row["version_id"],
                "size": file_row["size"],
                "content_hash": file_row["content_hash"],
                "created_at": now,
                "expires_at": expires,
                "max_downloads": max_downloads,
                "download_count": 0,
                "revoked_at": None,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def list_share_links(self, include_inactive: bool = False) -> list[dict]:
        now = utc_now()
        where = "" if include_inactive else "WHERE s.revoked_at IS NULL AND s.expires_at > ? AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)"
        params = () if include_inactive else (now,)
        conn = self._connect()
        try:
            rows = conn.execute(
                f"""
                SELECT s.id, s.virtual_path, s.version_id, s.created_at, s.expires_at,
                       s.max_downloads, s.download_count, s.last_downloaded_at, s.revoked_at,
                       v.size, v.content_hash,
                       CASE
                         WHEN s.revoked_at IS NOT NULL THEN 'revoked'
                         WHEN s.expires_at <= ? THEN 'expired'
                         WHEN s.max_downloads IS NOT NULL AND s.download_count >= s.max_downloads THEN 'exhausted'
                         ELSE 'active'
                       END AS state
                FROM share_links s JOIN versions v ON v.id = s.version_id
                {where}
                ORDER BY s.created_at DESC
                """,
                (now, *params),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def revoke_share_link(self, share_id: str) -> dict:
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM share_links WHERE id = ?", (share_id,)).fetchone()
            if row is None:
                raise FileNotFoundInVault(f"share link not found: {share_id}")
            if row["revoked_at"] is None:
                conn.execute("UPDATE share_links SET revoked_at = ? WHERE id = ?", (now, share_id))
                conn.execute(
                    "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('share.revoked', ?, ?, ?)",
                    (row["file_id"], row["version_id"], now),
                )
            conn.commit()
            return {"id": share_id, "revoked": True, "revoked_at": now}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def shared_download_manifest(self, raw_token: str) -> tuple[dict, list[dict]]:
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT s.*, v.size, v.content_hash
                FROM share_links s JOIN versions v ON v.id = s.version_id
                WHERE s.token_hash = ?
                """,
                (token_hash(raw_token),),
            ).fetchone()
            if row is None:
                raise FileNotFoundInVault("share link not found")
            if row["revoked_at"] is not None:
                raise FileNotFoundInVault("share link was revoked")
            if row["expires_at"] <= now:
                raise FileNotFoundInVault("share link has expired")
            if row["max_downloads"] is not None and row["download_count"] >= row["max_downloads"]:
                raise FileNotFoundInVault("share link download limit reached")
            conn.execute(
                "UPDATE share_links SET download_count = download_count + 1, last_downloaded_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            chunks = conn.execute(
                "SELECT ordinal, chunk_id, plain_size FROM version_chunks WHERE version_id = ? ORDER BY ordinal",
                (row["version_id"],),
            ).fetchall()
            conn.commit()
            info = {
                "share_id": row["id"],
                "virtual_path": row["virtual_path"],
                "version_id": row["version_id"],
                "size": row["size"],
                "content_hash": row["content_hash"],
            }
            return info, [dict(chunk) for chunk in chunks]
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _entity_from_manifest(value: dict | None, fallback_id: str, fallback_name: str) -> dict:
        value = value or {}
        entity_id = str(value.get("id") or fallback_id).strip()
        name = str(value.get("name") or fallback_name).strip()
        entity_type = str(value.get("type") or "unknown").strip()
        parent_id = value.get("parent_id") or value.get("parent")
        if not entity_id or not name:
            raise ValueError("entity id and name are required")
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"unsupported entity type: {entity_type}")
        return {
            "id": entity_id,
            "type": entity_type,
            "name": name,
            "parent_id": str(parent_id).strip() if parent_id else None,
            "verified": bool(value.get("verified", False)),
        }

    @staticmethod
    def _permission_from_manifest(value) -> dict:
        if isinstance(value, str):
            capability, separator, resource = value.partition(":")
            return {
                "capability": capability.strip(),
                "resource": resource.strip() if separator else "*",
                "description": None,
            }
        if not isinstance(value, dict):
            raise ValueError("plugin permission must be a string or object")
        return {
            "capability": str(value.get("capability", "")).strip(),
            "resource": str(value.get("resource", "*")).strip() or "*",
            "description": value.get("description"),
        }

    @staticmethod
    def _upsert_entity(conn: sqlite3.Connection, entity: dict, now: str) -> None:
        conn.execute(
            """
            INSERT INTO entities(id, type, name, parent_id, verified, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                type = excluded.type,
                name = excluded.name,
                parent_id = excluded.parent_id,
                verified = excluded.verified,
                updated_at = excluded.updated_at
            """,
            (
                entity["id"], entity["type"], entity["name"], entity["parent_id"],
                1 if entity["verified"] else 0, now, now,
            ),
        )

    def register_artifact_manifest(self, manifest: dict) -> dict:
        if not isinstance(manifest, dict):
            raise ValueError("artifact manifest must be an object")
        artifact_id = str(manifest.get("id", "")).strip()
        name = str(manifest.get("name", "")).strip()
        kind = str(manifest.get("kind", "plugin")).strip()
        version = str(manifest.get("version", "0.1.0")).strip()
        entry = manifest.get("entry")
        if not artifact_id or not name:
            raise ValueError("artifact id and name are required")
        if kind not in ARTIFACT_KINDS:
            raise ValueError(f"unsupported artifact kind: {kind}")
        publisher = self._entity_from_manifest(manifest.get("publisher"), f"entity.publisher.{artifact_id}", "Unknown Publisher")
        author = self._entity_from_manifest(manifest.get("author"), publisher["id"], publisher["name"])
        permissions = [self._permission_from_manifest(item) for item in manifest.get("permissions", [])]
        for permission in permissions:
            if not permission["capability"]:
                raise ValueError("permission capability is required")
        now = utc_now()
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._upsert_entity(conn, publisher, now)
            if author["id"] != publisher["id"]:
                self._upsert_entity(conn, author, now)
            row = conn.execute("SELECT status FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
            status = row["status"] if row is not None else "disabled"
            conn.execute(
                """
                INSERT INTO artifacts(id, kind, name, version, publisher_id, author_id, entry, status, manifest_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind = excluded.kind,
                    name = excluded.name,
                    version = excluded.version,
                    publisher_id = excluded.publisher_id,
                    author_id = excluded.author_id,
                    entry = excluded.entry,
                    manifest_json = excluded.manifest_json,
                    updated_at = excluded.updated_at
                """,
                (
                    artifact_id, kind, name, version, publisher["id"], author["id"],
                    str(entry).strip() if entry else None, status, manifest_json, now, now,
                ),
            )
            conn.execute("DELETE FROM artifact_permissions WHERE artifact_id = ?", (artifact_id,))
            for permission in permissions:
                conn.execute(
                    """
                    INSERT INTO artifact_permissions(artifact_id, capability, resource, description)
                    VALUES (?, ?, ?, ?)
                    """,
                    (artifact_id, permission["capability"], permission["resource"], permission["description"]),
                )
            conn.commit()
            return self.get_artifact(artifact_id)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_artifact(self, artifact_id: str) -> dict:
        items = self.list_artifacts()
        for item in items:
            if item["id"] == artifact_id:
                return item
        raise FileNotFoundInVault(f"artifact not found: {artifact_id}")

    def list_artifacts(self) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT a.*, p.name AS publisher_name, p.type AS publisher_type, p.parent_id AS publisher_parent_id,
                       au.name AS author_name, au.type AS author_type,
                       EXISTS(
                         SELECT 1 FROM entity_sanctions s
                         WHERE s.revoked_at IS NULL
                           AND s.action = 'deny'
                           AND (
                             s.target_entity_id = a.publisher_id
                             OR (s.scope IN ('children', 'all_children') AND s.target_entity_id = p.parent_id)
                           )
                       ) AS denied_by_sanction
                FROM artifacts a
                JOIN entities p ON p.id = a.publisher_id
                LEFT JOIN entities au ON au.id = a.author_id
                ORDER BY a.name COLLATE NOCASE
                """
            ).fetchall()
            results = []
            for row in rows:
                artifact = dict(row)
                permissions = conn.execute(
                    "SELECT capability, resource, description FROM artifact_permissions WHERE artifact_id = ? ORDER BY capability, resource",
                    (artifact["id"],),
                ).fetchall()
                sanctions = conn.execute(
                    """
                    SELECT s.id, s.target_entity_id, e.name AS target_name, s.scope, s.action, s.reason, s.created_at
                    FROM entity_sanctions s JOIN entities e ON e.id = s.target_entity_id
                    WHERE s.revoked_at IS NULL
                      AND (s.target_entity_id = ? OR s.target_entity_id = ? OR s.target_entity_id = ?)
                    ORDER BY s.created_at DESC
                    """,
                    (artifact["publisher_id"], artifact["author_id"], artifact["publisher_parent_id"]),
                ).fetchall()
                artifact["permissions"] = [dict(item) for item in permissions]
                artifact["sanctions"] = [dict(item) for item in sanctions]
                artifact["effective_status"] = "blocked" if artifact["denied_by_sanction"] else artifact["status"]
                results.append(artifact)
            return results
        finally:
            conn.close()

    def set_artifact_status(self, artifact_id: str, enabled: bool) -> dict:
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE artifacts SET status = ?, updated_at = ? WHERE id = ?",
                ("enabled" if enabled else "disabled", now, artifact_id),
            )
            if cursor.rowcount != 1:
                raise FileNotFoundInVault(f"artifact not found: {artifact_id}")
            conn.commit()
            return self.get_artifact(artifact_id)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def sanction_entity(self, entity_id: str, scope: str = "all_children", action: str = "deny", reason: str | None = None) -> dict:
        if scope not in ("self", "children", "all_children"):
            raise ValueError("unsupported sanction scope")
        if action not in ("deny", "require_confirmation"):
            raise ValueError("unsupported sanction action")
        now = utc_now()
        sanction_id = uuid.uuid4().hex
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            entity = conn.execute("SELECT id FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if entity is None:
                raise FileNotFoundInVault(f"entity not found: {entity_id}")
            conn.execute(
                """
                INSERT INTO entity_sanctions(id, target_entity_id, scope, action, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sanction_id, entity_id, scope, action, reason, now),
            )
            conn.commit()
            return {"id": sanction_id, "target_entity_id": entity_id, "scope": scope, "action": action, "reason": reason, "created_at": now}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def revoke_sanction(self, sanction_id: str) -> dict:
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute("UPDATE entity_sanctions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now, sanction_id))
            if cursor.rowcount != 1:
                raise FileNotFoundInVault(f"sanction not found: {sanction_id}")
            conn.commit()
            return {"id": sanction_id, "revoked": True, "revoked_at": now}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def iter_manifest(self, manifest: list[dict]):
        for chunk in manifest:
            plaintext = self.blobs.get(chunk["chunk_id"])
            if len(plaintext) != chunk["plain_size"]:
                raise IntegrityError(f"chunk size mismatch: {chunk['chunk_id']}")
            yield plaintext

    def delete_file(self, virtual_path: str) -> None:
        virtual_path = normalize_virtual_path(virtual_path)
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, current_version_id FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                (virtual_path,),
            ).fetchone()
            if row is None:
                raise FileNotFoundInVault(virtual_path)
            conn.execute("UPDATE files SET deleted_at = ? WHERE id = ?", (now, row["id"]))
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.deleted', ?, ?, ?)",
                (row["id"], row["current_version_id"], now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def restore_file(self, virtual_path: str) -> None:
        virtual_path = normalize_virtual_path(virtual_path)
        now = utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            deleted = conn.execute(
                """
                SELECT id, current_version_id FROM files
                WHERE virtual_path = ? AND deleted_at IS NOT NULL
                ORDER BY deleted_at DESC LIMIT 1
                """,
                (virtual_path,),
            ).fetchone()
            if deleted is None:
                raise FileNotFoundInVault(virtual_path)
            live = conn.execute(
                "SELECT 1 FROM files WHERE virtual_path = ? AND deleted_at IS NULL", (virtual_path,)
            ).fetchone()
            if live is not None:
                raise RestoreConflict(f"a live file already uses path: {virtual_path}")
            conn.execute("UPDATE files SET deleted_at = NULL WHERE id = ?", (deleted["id"],))
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.restored', ?, ?, ?)",
                (deleted["id"], deleted["current_version_id"], now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def restore_version(self, virtual_path: str, version_id: str) -> str:
        virtual_path = normalize_virtual_path(virtual_path)
        now = utc_now()
        new_version_id = uuid.uuid4().hex
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT f.id AS file_id, v.size, v.content_hash
                FROM files f JOIN versions v ON v.file_id = f.id
                WHERE f.virtual_path = ? AND f.deleted_at IS NULL AND v.id = ?
                """,
                (virtual_path, version_id),
            ).fetchone()
            if row is None:
                raise FileNotFoundInVault(f"{virtual_path} version {version_id}")
            conn.execute(
                "INSERT INTO versions(id, file_id, size, content_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (new_version_id, row["file_id"], row["size"], row["content_hash"], now),
            )
            chunks = conn.execute(
                "SELECT ordinal, chunk_id, plain_size FROM version_chunks WHERE version_id = ? ORDER BY ordinal",
                (version_id,),
            ).fetchall()
            for chunk in chunks:
                conn.execute(
                    "INSERT INTO version_chunks(version_id, ordinal, chunk_id, plain_size) VALUES (?, ?, ?, ?)",
                    (new_version_id, chunk["ordinal"], chunk["chunk_id"], chunk["plain_size"]),
                )
                conn.execute("UPDATE chunks SET ref_count = ref_count + 1 WHERE id = ?", (chunk["chunk_id"],))
            conn.execute("UPDATE files SET current_version_id = ? WHERE id = ?", (new_version_id, row["file_id"]))
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.version.restored', ?, ?, ?)",
                (row["file_id"], new_version_id, now),
            )
            conn.commit()
            return new_version_id
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def purge_file(self, virtual_path: str) -> dict:
        virtual_path = normalize_virtual_path(virtual_path)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT id FROM files WHERE virtual_path = ? AND deleted_at IS NOT NULL
                ORDER BY deleted_at DESC LIMIT 1
                """,
                (virtual_path,),
            ).fetchone()
            if row is None:
                raise FileNotFoundInVault(f"deleted file not found: {virtual_path}")
            counts = conn.execute(
                """
                SELECT vc.chunk_id, COUNT(*) AS uses
                FROM version_chunks vc JOIN versions v ON v.id = vc.version_id
                WHERE v.file_id = ? GROUP BY vc.chunk_id
                """,
                (row["id"],),
            ).fetchall()
            for count in counts:
                conn.execute(
                    "UPDATE chunks SET ref_count = ref_count - ? WHERE id = ?",
                    (count["uses"], count["chunk_id"]),
                )
            conn.execute(
                """
                DELETE FROM upload_sessions
                WHERE committed_version_id IN (SELECT id FROM versions WHERE file_id = ?)
                """,
                (row["id"],),
            )
            conn.execute(
                "DELETE FROM version_chunks WHERE version_id IN (SELECT id FROM versions WHERE file_id = ?)",
                (row["id"],),
            )
            conn.execute("DELETE FROM versions WHERE file_id = ?", (row["id"],))
            conn.execute("DELETE FROM events WHERE file_id = ?", (row["id"],))
            conn.execute("DELETE FROM files WHERE id = ?", (row["id"],))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        result = self.collect_garbage()
        result["purged_path"] = virtual_path
        return result

    def collect_garbage(self) -> dict:
        conn = self._connect()
        deleted_chunks = 0
        reclaimed_bytes = 0
        try:
            rows = conn.execute("SELECT id, stored_size FROM chunks WHERE ref_count = 0").fetchall()
            for row in rows:
                self.blobs.delete(row["id"])
                conn.execute("DELETE FROM chunks WHERE id = ? AND ref_count = 0", (row["id"],))
                deleted_chunks += 1
                reclaimed_bytes += row["stored_size"]
            conn.commit()
            return {"deleted_chunks": deleted_chunks, "reclaimed_bytes": reclaimed_bytes}
        finally:
            conn.close()

    def get_quota(self) -> int | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT value FROM vault_settings WHERE key = 'quota_bytes'").fetchone()
            return int(row["value"]) if row else None
        finally:
            conn.close()

    def set_quota(self, quota_bytes: int | None) -> None:
        if quota_bytes is not None and quota_bytes < 0:
            raise ValueError("quota cannot be negative")
        conn = self._connect()
        try:
            if quota_bytes is None:
                conn.execute("DELETE FROM vault_settings WHERE key = 'quota_bytes'")
            else:
                conn.execute(
                    "INSERT INTO vault_settings(key, value) VALUES ('quota_bytes', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(quota_bytes),),
                )
            conn.commit()
        finally:
            conn.close()

    def set_trash_retention(self, days: int | None) -> None:
        if days is not None and (days < 1 or days > 3650):
            raise ValueError("trash retention must be between 1 and 3650 days")
        conn = self._connect()
        try:
            if days is None:
                conn.execute("DELETE FROM vault_settings WHERE key = 'trash_retention_days'")
            else:
                conn.execute(
                    "INSERT INTO vault_settings(key, value) VALUES ('trash_retention_days', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(days),),
                )
            conn.commit()
        finally:
            conn.close()

    def get_trash_retention(self) -> int | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM vault_settings WHERE key = 'trash_retention_days'"
            ).fetchone()
            return int(row["value"]) if row else None
        finally:
            conn.close()

    def run_trash_retention(self, apply: bool = False) -> dict:
        days = self.get_trash_retention()
        if days is None:
            raise ValueError("trash retention policy is not configured")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        candidates = [
            item for item in self.list_deleted_files()
            if item["deleted_at"] and item["deleted_at"] <= cutoff
        ]
        result = {
            "retention_days": days,
            "cutoff": cutoff,
            "candidate_count": len(candidates),
            "candidates": [item["virtual_path"] for item in candidates],
            "applied": apply,
            "reclaimed_bytes": 0,
        }
        if apply:
            for item in candidates:
                purge = self.purge_file(item["virtual_path"])
                result["reclaimed_bytes"] += purge["reclaimed_bytes"]
        return result

    def create_upload(
        self,
        virtual_path: str,
        expected_size: int,
        idempotency_key: str,
        ttl_seconds: int = 3600,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> dict:
        virtual_path = normalize_virtual_path(virtual_path)
        if expected_size < 0:
            raise ValueError("expected size cannot be negative")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValueError("idempotency key must contain 1 to 200 characters")
        if ttl_seconds <= 0 or ttl_seconds > 7 * 24 * 3600:
            raise ValueError("upload TTL must be between 1 second and 7 days")
        if chunk_size <= 0 or chunk_size > DEFAULT_CHUNK_SIZE:
            raise ValueError(f"chunk size must be between 1 and {DEFAULT_CHUNK_SIZE}")
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM upload_sessions WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["virtual_path"] != virtual_path
                    or existing["expected_size"] != expected_size
                    or existing["chunk_size"] != chunk_size
                ):
                    raise UploadConflict("idempotency key was already used for another upload")
                if existing["state"] == "committed":
                    still_current = conn.execute(
                        """
                        SELECT 1 FROM files
                        WHERE virtual_path = ? AND deleted_at IS NULL AND current_version_id = ?
                        """,
                        (virtual_path, existing["committed_version_id"]),
                    ).fetchone()
                    if still_current is None:
                        conn.execute(
                            "UPDATE upload_sessions SET state = 'open', committed_version_id = NULL, "
                            "created_at = ?, expires_at = ? WHERE id = ?",
                            (now.isoformat(), expires.isoformat(), existing["id"]),
                        )
                        existing = conn.execute(
                            "SELECT * FROM upload_sessions WHERE id = ?", (existing["id"],)
                        ).fetchone()
                elif existing["state"] in ("aborted", "expired"):
                    conn.execute(
                        "DELETE FROM upload_session_chunks WHERE session_id = ?", (existing["id"],)
                    )
                    conn.execute(
                        "UPDATE upload_sessions SET state = 'open', committed_version_id = NULL, "
                        "created_at = ?, expires_at = ? WHERE id = ?",
                        (now.isoformat(), expires.isoformat(), existing["id"]),
                    )
                    existing = conn.execute(
                        "SELECT * FROM upload_sessions WHERE id = ?", (existing["id"],)
                    ).fetchone()
                conn.commit()
                return self._upload_row_to_dict(existing)
            session_id = uuid.uuid4().hex
            conn.execute(
                """
                INSERT INTO upload_sessions(
                    id, virtual_path, expected_size, chunk_size, idempotency_key,
                    state, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    session_id,
                    virtual_path,
                    expected_size,
                    chunk_size,
                    idempotency_key,
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )
            conn.commit()
            return self.get_upload(session_id)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _upload_row_to_dict(row, uploaded_chunks: list | None = None) -> dict:
        return {
            "id": row["id"],
            "virtual_path": row["virtual_path"],
            "expected_size": row["expected_size"],
            "chunk_size": row["chunk_size"],
            "idempotency_key": row["idempotency_key"],
            "state": row["state"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "committed_version_id": row["committed_version_id"],
            "uploaded_chunks": uploaded_chunks or [],
        }

    def get_upload(self, session_id: str) -> dict:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM upload_sessions WHERE id = ?", (session_id,)).fetchone()
            if row is None:
                raise UploadSessionNotFound(session_id)
            chunks = conn.execute(
                "SELECT ordinal, chunk_id, plain_size FROM upload_session_chunks "
                "WHERE session_id = ? ORDER BY ordinal",
                (session_id,),
            ).fetchall()
            return self._upload_row_to_dict(row, [dict(chunk) for chunk in chunks])
        finally:
            conn.close()

    def _require_open_upload(self, conn: sqlite3.Connection, session_id: str):
        row = conn.execute("SELECT * FROM upload_sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            raise UploadSessionNotFound(session_id)
        if row["state"] != "open":
            if row["state"] == "expired":
                raise UploadSessionExpired(session_id)
            raise UploadConflict(f"upload session is {row['state']}")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            conn.execute("UPDATE upload_sessions SET state = 'expired' WHERE id = ?", (session_id,))
            conn.commit()
            raise UploadSessionExpired(session_id)
        return row

    def upload_chunk(self, session_id: str, ordinal: int, plaintext: bytes) -> dict:
        if ordinal < 0:
            raise ValueError("chunk ordinal cannot be negative")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            session = self._require_open_upload(conn, session_id)
            chunk_count = (session["expected_size"] + session["chunk_size"] - 1) // session["chunk_size"]
            if ordinal >= chunk_count:
                raise UploadConflict("chunk ordinal is outside the expected file")
            expected_chunk_size = session["chunk_size"]
            if ordinal == chunk_count - 1:
                expected_chunk_size = session["expected_size"] - ordinal * session["chunk_size"]
            if len(plaintext) != expected_chunk_size:
                raise UploadConflict(
                    f"chunk {ordinal} must contain {expected_chunk_size} bytes, got {len(plaintext)}"
                )
            chunk_id = self.blobs.cipher.chunk_id(plaintext)
            existing = conn.execute(
                "SELECT chunk_id, plain_size FROM upload_session_chunks WHERE session_id = ? AND ordinal = ?",
                (session_id, ordinal),
            ).fetchone()
            if existing is not None:
                if existing["chunk_id"] != chunk_id or existing["plain_size"] != len(plaintext):
                    raise UploadConflict(f"chunk {ordinal} was already uploaded with different content")
                conn.commit()
                return {"ordinal": ordinal, "chunk_id": chunk_id, "deduplicated": True}

            quota = self.get_quota()
            if not self.blobs.exists(chunk_id) and quota is not None:
                needed = len(plaintext) + BLOB_OVERHEAD
                available = max(quota - self.blobs.disk_usage(), 0)
                if needed > available:
                    raise QuotaExceeded(
                        f"vault quota exceeded: need {needed} additional bytes, {available} available"
                    )
            stored_size, created = self.blobs.put(chunk_id, plaintext)
            conn.execute(
                """
                INSERT INTO upload_session_chunks(session_id, ordinal, chunk_id, plain_size, stored_size)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, ordinal, chunk_id, len(plaintext), stored_size),
            )
            conn.commit()
            return {"ordinal": ordinal, "chunk_id": chunk_id, "deduplicated": not created}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def commit_upload(self, session_id: str) -> dict:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM upload_sessions WHERE id = ?", (session_id,)).fetchone()
            if existing is None:
                raise UploadSessionNotFound(session_id)
            if existing["state"] == "committed":
                conn.commit()
                return {"session_id": session_id, "version_id": existing["committed_version_id"], "committed": True}
            session = self._require_open_upload(conn, session_id)
            chunks = conn.execute(
                "SELECT ordinal, chunk_id, plain_size, stored_size FROM upload_session_chunks "
                "WHERE session_id = ? ORDER BY ordinal",
                (session_id,),
            ).fetchall()
            expected_count = (session["expected_size"] + session["chunk_size"] - 1) // session["chunk_size"]
            if len(chunks) != expected_count or any(chunk["ordinal"] != index for index, chunk in enumerate(chunks)):
                raise UploadConflict("upload is incomplete")
            digest = hashlib.sha256()
            total_size = 0
            for chunk in chunks:
                plaintext = self.blobs.get(chunk["chunk_id"])
                if len(plaintext) != chunk["plain_size"]:
                    raise IntegrityError(f"chunk size mismatch: {chunk['chunk_id']}")
                digest.update(plaintext)
                total_size += len(plaintext)
            if total_size != session["expected_size"]:
                raise UploadConflict("uploaded size does not match expected size")

            content_hash = digest.hexdigest()
            file_row = conn.execute(
                "SELECT id, current_version_id FROM files WHERE virtual_path = ? AND deleted_at IS NULL",
                (session["virtual_path"],),
            ).fetchone()
            if file_row is not None and file_row["current_version_id"]:
                current = conn.execute(
                    "SELECT id, size, content_hash FROM versions WHERE id = ?",
                    (file_row["current_version_id"],),
                ).fetchone()
                if current["size"] == total_size and current["content_hash"] == content_hash:
                    conn.execute(
                        "UPDATE upload_sessions SET state = 'committed', committed_version_id = ? WHERE id = ?",
                        (current["id"], session_id),
                    )
                    conn.commit()
                    return {"session_id": session_id, "version_id": current["id"], "committed": True, "unchanged": True}

            now = utc_now()
            file_id = file_row["id"] if file_row else uuid.uuid4().hex
            version_id = uuid.uuid4().hex
            if file_row is None:
                self._ensure_directories(conn, session["virtual_path"], now)
                conn.execute(
                    "INSERT INTO files(id, virtual_path, created_at) VALUES (?, ?, ?)",
                    (file_id, session["virtual_path"], now),
                )
            conn.execute(
                "INSERT INTO versions(id, file_id, size, content_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (version_id, file_id, total_size, content_hash, now),
            )
            for chunk in chunks:
                stored = conn.execute("SELECT plain_size FROM chunks WHERE id = ?", (chunk["chunk_id"],)).fetchone()
                if stored is None:
                    conn.execute(
                        "INSERT INTO chunks(id, ref_count, plain_size, stored_size, created_at) VALUES (?, 1, ?, ?, ?)",
                        (chunk["chunk_id"], chunk["plain_size"], chunk["stored_size"], now),
                    )
                else:
                    if stored["plain_size"] != chunk["plain_size"]:
                        raise IntegrityError("chunk metadata collision")
                    conn.execute("UPDATE chunks SET ref_count = ref_count + 1 WHERE id = ?", (chunk["chunk_id"],))
                conn.execute(
                    "INSERT INTO version_chunks(version_id, ordinal, chunk_id, plain_size) VALUES (?, ?, ?, ?)",
                    (version_id, chunk["ordinal"], chunk["chunk_id"], chunk["plain_size"]),
                )
            conn.execute("UPDATE files SET current_version_id = ? WHERE id = ?", (version_id, file_id))
            conn.execute(
                "UPDATE upload_sessions SET state = 'committed', committed_version_id = ? WHERE id = ?",
                (version_id, session_id),
            )
            conn.execute(
                "INSERT INTO events(event_type, file_id, version_id, occurred_at) VALUES ('file.version.created', ?, ?, ?)",
                (file_id, version_id, now),
            )
            conn.commit()
            return {"session_id": session_id, "version_id": version_id, "committed": True, "unchanged": False}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def abort_upload(self, session_id: str) -> dict:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT state FROM upload_sessions WHERE id = ?", (session_id,)).fetchone()
            if row is None:
                raise UploadSessionNotFound(session_id)
            if row["state"] == "committed":
                raise UploadConflict("committed upload cannot be aborted")
            if row["state"] == "open":
                conn.execute("UPDATE upload_sessions SET state = 'aborted' WHERE id = ?", (session_id,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        result = self.collect_orphan_blobs()
        result.update({"session_id": session_id, "state": "aborted"})
        return result

    def cleanup_uploads(self) -> dict:
        now = utc_now()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE upload_sessions SET state = 'expired' WHERE state = 'open' AND expires_at <= ?",
                (now,),
            )
            expired = cursor.rowcount
            conn.commit()
        finally:
            conn.close()
        result = self.collect_orphan_blobs()
        result["expired_sessions"] = expired
        return result

    def collect_orphan_blobs(self) -> dict:
        conn = self._connect()
        try:
            referenced = {row[0] for row in conn.execute("SELECT id FROM chunks WHERE ref_count > 0")}
            referenced.update(
                row[0]
                for row in conn.execute(
                    """
                    SELECT DISTINCT usc.chunk_id FROM upload_session_chunks usc
                    JOIN upload_sessions us ON us.id = usc.session_id WHERE us.state = 'open'
                    """
                )
            )
        finally:
            conn.close()
        orphan_ids = self.blobs.stored_chunk_ids() - referenced
        reclaimed = 0
        for chunk_id in orphan_ids:
            path = self.blobs.path_for(chunk_id)
            if path.exists():
                reclaimed += path.stat().st_size
                self.blobs.delete(chunk_id)
        return {"deleted_orphan_blobs": len(orphan_ids), "reclaimed_bytes": reclaimed}

    def status(self) -> dict:
        conn = self._connect()
        try:
            live = conn.execute("SELECT COUNT(*) FROM files WHERE deleted_at IS NULL").fetchone()[0]
            deleted = conn.execute("SELECT COUNT(*) FROM files WHERE deleted_at IS NOT NULL").fetchone()[0]
            versions = conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0]
            chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            logical = conn.execute("SELECT COALESCE(SUM(size), 0) FROM versions").fetchone()[0]
            stored = conn.execute("SELECT COALESCE(SUM(stored_size), 0) FROM chunks").fetchone()[0]
            return {
                "live_files": live,
                "deleted_files": deleted,
                "versions": versions,
                "chunks": chunks,
                "logical_bytes": logical,
                "stored_bytes": stored,
                "physical_bytes": self.blobs.disk_usage(),
                "quota_bytes": self.get_quota(),
            }
        finally:
            conn.close()

    def verify(self) -> dict:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT id, plain_size FROM chunks ORDER BY id").fetchall()
        finally:
            conn.close()
        checked_bytes = 0
        for row in rows:
            plaintext = self.blobs.get(row["id"])
            if len(plaintext) != row["plain_size"]:
                raise IntegrityError(f"chunk size mismatch: {row['id']}")
            checked_bytes += len(plaintext)
        return {"checked_chunks": len(rows), "checked_bytes": checked_bytes}
