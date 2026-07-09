import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 8

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    virtual_path TEXT NOT NULL,
    current_version_id TEXT,
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_live_file_path
ON files(virtual_path) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS versions (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id),
    size INTEGER NOT NULL CHECK(size >= 0),
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    ref_count INTEGER NOT NULL CHECK(ref_count >= 0),
    plain_size INTEGER NOT NULL CHECK(plain_size >= 0),
    stored_size INTEGER NOT NULL CHECK(stored_size >= 0),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS version_chunks (
    version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    chunk_id TEXT NOT NULL REFERENCES chunks(id),
    plain_size INTEGER NOT NULL CHECK(plain_size >= 0),
    PRIMARY KEY(version_id, ordinal)
);

CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    file_id TEXT NOT NULL,
    version_id TEXT,
    occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    virtual_path TEXT NOT NULL,
    expected_size INTEGER NOT NULL CHECK(expected_size >= 0),
    chunk_size INTEGER NOT NULL CHECK(chunk_size > 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('open', 'committed', 'aborted', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    committed_version_id TEXT
);

CREATE TABLE IF NOT EXISTS upload_session_chunks (
    session_id TEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    chunk_id TEXT NOT NULL,
    plain_size INTEGER NOT NULL CHECK(plain_size >= 0),
    stored_size INTEGER NOT NULL CHECK(stored_size >= 0),
    PRIMARY KEY(session_id, ordinal)
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
    created_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS pairing_sessions (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS access_tokens (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_challenges (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS action_tokens (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS directories (
    virtual_path TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS share_links (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    virtual_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_downloads INTEGER CHECK(max_downloads IS NULL OR max_downloads > 0),
    download_count INTEGER NOT NULL DEFAULT 0 CHECK(download_count >= 0),
    last_downloaded_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('person', 'organization', 'user', 'agent', 'unknown')),
    name TEXT NOT NULL,
    parent_id TEXT REFERENCES entities(id),
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('plugin', 'skill', 'app', 'work')),
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    publisher_id TEXT NOT NULL REFERENCES entities(id),
    author_id TEXT REFERENCES entities(id),
    entry TEXT,
    status TEXT NOT NULL CHECK(status IN ('enabled', 'disabled')),
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_permissions (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '*',
    description TEXT,
    PRIMARY KEY(artifact_id, capability, resource)
);

CREATE TABLE IF NOT EXISTS entity_sanctions (
    id TEXT PRIMARY KEY,
    target_entity_id TEXT NOT NULL REFERENCES entities(id),
    scope TEXT NOT NULL CHECK(scope IN ('self', 'children', 'all_children')),
    action TEXT NOT NULL CHECK(action IN ('deny', 'require_confirmation')),
    reason TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
"""


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def initialize(path: Path) -> None:
    existing_version = schema_version(path)
    if existing_version is not None and existing_version < SCHEMA_VERSION:
        backup_database(path, path.parent / "backups", "pre-migration")
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
        if row is None:
            conn.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] in (1, 2, 3, 4, 5, 6, 7):
            conn.execute("UPDATE schema_info SET version = ?", (SCHEMA_VERSION,))
        elif row["version"] != SCHEMA_VERSION:
            raise RuntimeError(f"unsupported schema version: {row['version']}")
        conn.commit()
    finally:
        conn.close()


def schema_version(path: Path) -> int | None:
    if not path.exists():
        return None
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_info'"
        ).fetchone()
        if row is None:
            return None
        version = conn.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
        return int(version[0]) if version else None
    finally:
        conn.close()


def backup_database(path: Path, backup_directory: Path, label: str = "manual") -> dict:
    backup_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    version = schema_version(path)
    backup_path = backup_directory / f"metadata-{timestamp}-schema{version or 0}-{label}.sqlite3"
    source = sqlite3.connect(path)
    destination = sqlite3.connect(backup_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()
    digest = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    manifest = {
        "database": backup_path.name,
        "sha256": digest,
        "schema_version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
    }
    manifest_path = backup_path.with_suffix(".json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {**manifest, "path": str(backup_path), "manifest_path": str(manifest_path)}


def restore_database(current_path: Path, backup_path: Path) -> dict:
    backup_path = backup_path.resolve()
    if not backup_path.is_file():
        raise FileNotFoundError(backup_path)
    manifest_path = backup_path.with_suffix(".json")
    if not manifest_path.is_file():
        raise ValueError("backup manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    if digest != manifest.get("sha256"):
        raise ValueError("metadata backup checksum mismatch")
    source = sqlite3.connect(backup_path)
    try:
        integrity = source.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(f"metadata backup integrity check failed: {integrity}")
        backup_version = source.execute("SELECT version FROM schema_info LIMIT 1").fetchone()[0]
        if backup_version > SCHEMA_VERSION:
            raise ValueError("metadata backup uses a newer unsupported schema")
        safety = backup_database(current_path, current_path.parent / "backups", "pre-restore")
        destination = sqlite3.connect(current_path)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    initialize(current_path)
    return {"restored_from": str(backup_path), "safety_backup": safety["path"]}
