import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import __version__
from .database import SCHEMA_VERSION
from .errors import IntegrityError


FORMAT = "psn-drive-disaster-backup-v1"
MANIFEST_NAME = "psn-disaster-manifest.json"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def safe_label(value: str) -> str:
    allowed = []
    for char in value.strip().lower() or "manual":
        if char.isalnum() or char in ("-", "_"):
            allowed.append(char)
        elif char in (" ", ".", ":"):
            allowed.append("-")
    result = "".join(allowed).strip("-_")
    return result or "manual"


def _iter_backup_sources(control: Path, metadata_snapshot: Path) -> list[tuple[Path, str]]:
    sources: list[tuple[Path, str]] = [(metadata_snapshot, ".psn/metadata.sqlite3")]
    for name in ("master.key", "tls.crt", "tls.key"):
        path = control / name
        if path.is_file():
            sources.append((path, f".psn/{name}"))
    blobs = control / "blobs"
    if blobs.exists():
        for path in sorted(blobs.rglob("*")):
            if path.is_file():
                sources.append((path, f".psn/{path.relative_to(control).as_posix()}"))
    return sources


def _validate_archive_member(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or name in ("", "."):
        raise ValueError(f"unsafe backup member path: {name!r}")


def create_disaster_backup(vault, destination: Path | str | None = None, label: str = "manual") -> dict:
    control = vault.control
    if destination is None:
        backup_dir = control / "disaster-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        destination_path = backup_dir / f"psn-drive-{utc_timestamp()}-{safe_label(label)}.tar"
    else:
        destination_path = Path(destination).expanduser().resolve()
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.suffix.lower() != ".tar":
            raise ValueError("disaster backup file must use .tar extension")
    if destination_path.exists():
        raise FileExistsError(destination_path)

    with tempfile.TemporaryDirectory(prefix="psn-disaster-backup-", dir=destination_path.parent) as temporary_directory:
        temporary = Path(temporary_directory)
        metadata_snapshot = temporary / "metadata.sqlite3"
        source = sqlite3.connect(vault.database_path)
        snapshot = sqlite3.connect(metadata_snapshot)
        try:
            source.backup(snapshot)
        finally:
            snapshot.close()
            source.close()

        source_pairs = _iter_backup_sources(control, metadata_snapshot)
        files = []
        for source_path, archive_path in source_pairs:
            files.append(
                {
                    "path": archive_path,
                    "size": source_path.stat().st_size,
                    "sha256": sha256_file(source_path),
                }
            )

        required = {item["path"] for item in files}
        for name in (".psn/metadata.sqlite3", ".psn/master.key"):
            if name not in required:
                raise FileNotFoundError(f"required vault control file is missing: {name}")

        manifest = {
            "format": FORMAT,
            "tool_version": __version__,
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "label": label,
            "vault_root": str(vault.root),
            "files": files,
        }
        manifest_path = temporary / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        temporary_archive = destination_path.with_name(f".{destination_path.name}.{os.getpid()}.tmp")
        try:
            with tarfile.open(temporary_archive, "w", format=tarfile.PAX_FORMAT) as archive:
                archive.add(manifest_path, arcname=MANIFEST_NAME, recursive=False)
                for source_path, archive_path in source_pairs:
                    archive.add(source_path, arcname=archive_path, recursive=False)
            archive_sha256 = sha256_file(temporary_archive)
            os.replace(temporary_archive, destination_path)
        finally:
            temporary_archive.unlink(missing_ok=True)

    sidecar = {
        "format": FORMAT,
        "archive": destination_path.name,
        "archive_sha256": archive_sha256,
        "created_at": manifest["created_at"],
        "label": label,
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "file_count": len(files),
        "total_payload_bytes": sum(item["size"] for item in files),
    }
    sidecar_path = destination_path.with_suffix(".json")
    sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=False, indent=2), encoding="utf-8")
    return {**sidecar, "path": str(destination_path), "manifest_path": str(sidecar_path)}


def list_disaster_backups(control: Path) -> list[dict]:
    backup_dir = control / "disaster-backups"
    if not backup_dir.exists():
        return []
    results = []
    for manifest_path in sorted(backup_dir.glob("psn-drive-*.json"), reverse=True):
        try:
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            archive_path = backup_dir / value["archive"]
            value["path"] = str(archive_path)
            value["manifest_path"] = str(manifest_path)
            value["archive_exists"] = archive_path.is_file()
            results.append(value)
        except (OSError, ValueError, KeyError):
            continue
    return results


def _extract_and_verify(archive_path: Path, destination: Path) -> dict:
    archive_path = archive_path.expanduser().resolve()
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    with tarfile.open(archive_path, "r") as archive:
        members = archive.getmembers()
        for member in members:
            _validate_archive_member(member.name)
            if not member.isfile():
                raise ValueError(f"unsupported backup member type: {member.name}")
        manifest_member = archive.getmember(MANIFEST_NAME)
        manifest_file = archive.extractfile(manifest_member)
        if manifest_file is None:
            raise ValueError("backup manifest is unreadable")
        manifest = json.loads(manifest_file.read().decode("utf-8"))
        if manifest.get("format") != FORMAT:
            raise ValueError("unsupported disaster backup format")
        expected = {item["path"]: item for item in manifest.get("files", [])}
        for required in (".psn/metadata.sqlite3", ".psn/master.key"):
            if required not in expected:
                raise ValueError(f"backup is missing required file: {required}")
        for member in members:
            if member.name == MANIFEST_NAME:
                continue
            if member.name not in expected:
                raise ValueError(f"backup contains unexpected file: {member.name}")
        archive.extractall(destination, filter="data")

    for item in expected.values():
        path = destination / item["path"]
        if not path.is_file():
            raise ValueError(f"backup did not extract expected file: {item['path']}")
        if path.stat().st_size != item["size"]:
            raise IntegrityError(f"backup file size mismatch: {item['path']}")
        if sha256_file(path) != item["sha256"]:
            raise IntegrityError(f"backup file checksum mismatch: {item['path']}")

    database_path = destination / ".psn" / "metadata.sqlite3"
    connection = sqlite3.connect(database_path)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise IntegrityError(f"restored metadata integrity check failed: {integrity}")
        version = connection.execute("SELECT version FROM schema_info LIMIT 1").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValueError("backup uses a newer unsupported schema")
    finally:
        connection.close()
    return manifest


def restore_disaster_backup(archive: Path | str, root: Path | str, force: bool = False) -> dict:
    root_path = Path(root).expanduser().resolve()
    control = root_path / ".psn"
    if control.exists() and not force:
        raise FileExistsError(f"target already contains a vault; use --force to keep a safety copy and replace it: {root_path}")
    root_path.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="psn-disaster-restore-", dir=root_path.parent) as temporary_directory:
        temporary = Path(temporary_directory)
        manifest = _extract_and_verify(Path(archive), temporary)
        restored_control = temporary / ".psn"
        if control.exists():
            safety = root_path / f".psn.restore-safety-{utc_timestamp()}"
            os.replace(control, safety)
        else:
            safety = None
        try:
            shutil.copytree(restored_control, control)
        except Exception:
            if safety is not None and not control.exists():
                os.replace(safety, control)
            raise

    return {
        "restored": True,
        "root": str(root_path),
        "format": manifest["format"],
        "created_at": manifest.get("created_at"),
        "file_count": len(manifest.get("files", [])),
        "safety_backup": str(safety) if safety is not None else None,
    }
