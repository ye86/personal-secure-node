import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .device_client import login_device, pinned_raw_request, pinned_request
from .errors import DriveError, HTTPClientError
from .tls import normalize_fingerprint
from .vault import DEFAULT_CHUNK_SIZE, normalize_virtual_path
from .sync_lock import SyncLock

STATE_DIRECTORY = ".psn-sync"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SyncConfig:
    node_url: str
    certificate_fingerprint: str
    device_id: str
    key_file: str
    local_root: str
    remote_prefix: str

    @classmethod
    def load(cls, path: Path | str) -> "SyncConfig":
        config_path = Path(path).resolve()
        value = json.loads(config_path.read_text(encoding="utf-8"))
        config = cls(**value)
        config.validate()
        return config

    def validate(self) -> None:
        if not self.node_url.startswith("https://"):
            raise ValueError("sync node URL must use https")
        normalize_fingerprint(self.certificate_fingerprint)
        if not self.device_id:
            raise ValueError("device ID is required")
        root = Path(self.local_root).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"local sync root is not a directory: {root}")
        key = Path(self.key_file).expanduser().resolve()
        if not key.is_file():
            raise ValueError(f"device key does not exist: {key}")
        if self.remote_prefix:
            normalize_virtual_path(self.remote_prefix)

    def save(self, path: Path | str) -> None:
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(target)
        target.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")


class SyncState:
    def __init__(self, root: Path):
        self.directory = root / STATE_DIRECTORY
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "state.sqlite3"
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS synced_files (
                relative_path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                remote_path TEXT NOT NULL,
                version_id TEXT NOT NULL,
                synced_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('synced', 'missing'))
            );
            CREATE TABLE IF NOT EXISTS sync_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                scanned INTEGER NOT NULL DEFAULT 0,
                uploaded INTEGER NOT NULL DEFAULT 0,
                unchanged INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                missing INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


class SyncClient:
    def __init__(self, config: SyncConfig):
        config.validate()
        self.config = config
        self.root = Path(config.local_root).expanduser().resolve()
        self.key_file = Path(config.key_file).expanduser().resolve()
        self.state = SyncState(self.root)
        self.access_token: str | None = None

    def close(self) -> None:
        self.state.close()

    def lock(self) -> SyncLock:
        return SyncLock(self.state.directory / "sync.lock")

    def login(self) -> None:
        response = login_device(
            self.config.node_url,
            self.config.certificate_fingerprint,
            self.config.device_id,
            self.key_file,
        )
        self.access_token = response["access_token"]

    def _request_json(self, method: str, path: str, value: dict | None = None) -> dict:
        if not self.access_token:
            self.login()
        try:
            _, body, _ = pinned_request(
                self.config.node_url,
                self.config.certificate_fingerprint,
                method,
                path,
                value,
                self.access_token,
            )
        except HTTPClientError as exc:
            if exc.status != 401:
                raise
            self.login()
            _, body, _ = pinned_request(
                self.config.node_url,
                self.config.certificate_fingerprint,
                method,
                path,
                value,
                self.access_token,
            )
        return json.loads(body)

    def _put_chunk(self, session_id: str, ordinal: int, chunk: bytes) -> dict:
        if not self.access_token:
            self.login()
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(chunk)),
        }
        try:
            _, body, _ = pinned_raw_request(
                self.config.node_url,
                self.config.certificate_fingerprint,
                "PUT",
                f"/v1/uploads/{session_id}/chunks/{ordinal}",
                chunk,
                headers,
            )
        except HTTPClientError as exc:
            if exc.status != 401:
                raise
            self.login()
            headers["Authorization"] = f"Bearer {self.access_token}"
            _, body, _ = pinned_raw_request(
                self.config.node_url,
                self.config.certificate_fingerprint,
                "PUT",
                f"/v1/uploads/{session_id}/chunks/{ordinal}",
                chunk,
                headers,
            )
        return json.loads(body)

    def scan_files(self):
        config_key = self.key_file
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            directory_path = Path(directory)
            dirs[:] = [
                name
                for name in dirs
                if name != STATE_DIRECTORY and not (directory_path / name).is_symlink()
            ]
            for name in files:
                path = directory_path / name
                if path.is_symlink() or path.resolve() == config_key:
                    continue
                relative = path.relative_to(self.root).as_posix()
                yield relative, path

    def remote_path(self, relative_path: str) -> str:
        relative = PurePosixPath(relative_path).as_posix()
        if self.config.remote_prefix:
            return normalize_virtual_path(f"{self.config.remote_prefix}/{relative}")
        return normalize_virtual_path(relative)

    @staticmethod
    def hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(DEFAULT_CHUNK_SIZE):
                digest.update(chunk)
        return digest.hexdigest()

    def upload_file(self, relative_path: str, path: Path, stat_before, content_hash: str) -> str:
        remote_path = self.remote_path(relative_path)
        path_id = hashlib.sha256(remote_path.encode("utf-8")).hexdigest()[:24]
        idempotency_key = f"sync-v1-{self.config.device_id}-{path_id}-{content_hash}"
        session = self._request_json(
            "POST",
            "/v1/uploads",
            {
                "virtual_path": remote_path,
                "expected_size": stat_before.st_size,
                "chunk_size": DEFAULT_CHUNK_SIZE,
                "idempotency_key": idempotency_key,
                "ttl_seconds": 24 * 3600,
            },
        )
        if session["state"] == "committed":
            return session["committed_version_id"]
        uploaded = {chunk["ordinal"] for chunk in session["uploaded_chunks"]}
        with path.open("rb") as handle:
            ordinal = 0
            while True:
                chunk = handle.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                if ordinal not in uploaded:
                    self._put_chunk(session["id"], ordinal, chunk)
                ordinal += 1
        result = self._request_json("POST", f"/v1/uploads/{session['id']}/commit", {})
        stat_after = path.stat()
        if stat_after.st_size != stat_before.st_size or stat_after.st_mtime_ns != stat_before.st_mtime_ns:
            raise DriveError(f"file changed during upload and will be retried: {relative_path}")
        return result["version_id"]

    def run(self, full_scan: bool = False, acquire_lock: bool = True) -> dict:
        if acquire_lock:
            with self.lock():
                return self.run(full_scan, acquire_lock=False)
        run_id = uuid.uuid4().hex
        started = utc_now()
        self.state.connection.execute(
            "INSERT INTO sync_runs(id, started_at) VALUES (?, ?)", (run_id, started)
        )
        self.state.connection.commit()
        report = {"run_id": run_id, "scanned": 0, "uploaded": 0, "unchanged": 0, "failed": 0, "missing": 0, "errors": []}
        seen = set()
        for relative_path, path in self.scan_files():
            report["scanned"] += 1
            seen.add(relative_path)
            try:
                stat_before = path.stat()
                previous = self.state.connection.execute(
                    "SELECT * FROM synced_files WHERE relative_path = ?", (relative_path,)
                ).fetchone()
                if (
                    not full_scan
                    and previous is not None
                    and previous["status"] == "synced"
                    and previous["size"] == stat_before.st_size
                    and previous["mtime_ns"] == stat_before.st_mtime_ns
                ):
                    report["unchanged"] += 1
                    continue
                content_hash = self.hash_file(path)
                if previous is not None and previous["content_hash"] == content_hash and previous["status"] == "synced":
                    self.state.connection.execute(
                        "UPDATE synced_files SET size = ?, mtime_ns = ? WHERE relative_path = ?",
                        (stat_before.st_size, stat_before.st_mtime_ns, relative_path),
                    )
                    self.state.connection.commit()
                    report["unchanged"] += 1
                    continue
                version_id = self.upload_file(relative_path, path, stat_before, content_hash)
                self.state.connection.execute(
                    """
                    INSERT INTO synced_files(
                        relative_path, size, mtime_ns, content_hash, remote_path,
                        version_id, synced_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced')
                    ON CONFLICT(relative_path) DO UPDATE SET
                        size = excluded.size, mtime_ns = excluded.mtime_ns,
                        content_hash = excluded.content_hash, remote_path = excluded.remote_path,
                        version_id = excluded.version_id, synced_at = excluded.synced_at,
                        status = 'synced'
                    """,
                    (
                        relative_path,
                        stat_before.st_size,
                        stat_before.st_mtime_ns,
                        content_hash,
                        self.remote_path(relative_path),
                        version_id,
                        utc_now(),
                    ),
                )
                self.state.connection.commit()
                report["uploaded"] += 1
            except Exception as exc:
                report["failed"] += 1
                report["errors"].append({"path": relative_path, "message": str(exc)})

        known = self.state.connection.execute(
            "SELECT relative_path FROM synced_files WHERE status = 'synced'"
        ).fetchall()
        for row in known:
            if row["relative_path"] not in seen:
                self.state.connection.execute(
                    "UPDATE synced_files SET status = 'missing' WHERE relative_path = ?",
                    (row["relative_path"],),
                )
                report["missing"] += 1
        self.state.connection.execute(
            """
            UPDATE sync_runs SET finished_at = ?, scanned = ?, uploaded = ?,
                unchanged = ?, failed = ?, missing = ? WHERE id = ?
            """,
            (
                utc_now(), report["scanned"], report["uploaded"], report["unchanged"],
                report["failed"], report["missing"], run_id,
            ),
        )
        self.state.connection.commit()
        return report

    def status(self) -> dict:
        counts = {
            row["status"]: row["count"]
            for row in self.state.connection.execute(
                "SELECT status, COUNT(*) AS count FROM synced_files GROUP BY status"
            )
        }
        latest = self.state.connection.execute(
            "SELECT * FROM sync_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return {
            "local_root": str(self.root),
            "remote_prefix": self.config.remote_prefix,
            "synced_files": counts.get("synced", 0),
            "missing_local_files": counts.get("missing", 0),
            "latest_run": dict(latest) if latest else None,
        }
