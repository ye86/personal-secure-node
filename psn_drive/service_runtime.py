import contextlib
import hashlib
import json
import os
import platform
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .database import schema_version
from .errors import ServiceAlreadyRunning, SyncAlreadyRunning
from .server_config import ServerConfig
from .sync_lock import SyncLock


LOCK_FILE = "server.lock"
STATE_FILE = "server.json"
LOG_FILE = "server.log"
MAX_LOG_BYTES = 5 * 1024 * 1024
DIAGNOSTIC_LOG_TAIL_BYTES = 512 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_directory(vault) -> Path:
    return vault.control / "run"


def logs_directory(vault) -> Path:
    return vault.control / "logs"


def diagnostics_directory(vault) -> Path:
    return vault.control / "diagnostics"


def service_lock_path(vault) -> Path:
    return run_directory(vault) / LOCK_FILE


def service_state_path(vault) -> Path:
    return run_directory(vault) / STATE_FILE


def service_log_path(vault) -> Path:
    return logs_directory(vault) / LOG_FILE


class ServiceLock:
    def __init__(self, vault):
        self.vault = vault
        self.path = service_lock_path(vault)
        self._lock = SyncLock(self.path)

    def __enter__(self):
        try:
            self._lock.__enter__()
        except SyncAlreadyRunning as exc:
            raise ServiceAlreadyRunning(f"another PSN Drive server holds {self.path}") from exc
        metadata = {
            "pid": os.getpid(),
            "started_at": utc_now(),
            "version": __version__,
        }
        service_state_path(self.vault).write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        service_state_path(self.vault).unlink(missing_ok=True)
        return self._lock.__exit__(exc_type, exc_value, traceback)


def rotate_log_if_needed(path: Path, max_bytes: int = MAX_LOG_BYTES) -> None:
    if path.exists() and path.stat().st_size >= max_bytes:
        rotated = path.with_name(f"{path.stem}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}{path.suffix}")
        os.replace(path, rotated)


@contextlib.contextmanager
def service_logging(vault):
    path = service_log_path(vault)
    path.parent.mkdir(parents=True, exist_ok=True)
    rotate_log_if_needed(path)
    with path.open("a", encoding="utf-8", buffering=1) as handle:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = handle
        sys.stderr = handle
        try:
            print(json.dumps({"event": "service.starting", "at": utc_now(), "version": __version__}, ensure_ascii=False), flush=True)
            yield path
            print(json.dumps({"event": "service.stopped", "at": utc_now()}, ensure_ascii=False), flush=True)
        except Exception as exc:
            print(
                json.dumps(
                    {"event": "service.failed", "at": utc_now(), "error": exc.__class__.__name__, "message": str(exc)},
                    ensure_ascii=False,
                ),
                flush=True,
            )
            raise
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr


def service_status(vault, config: ServerConfig | None = None) -> dict:
    lock_path = service_lock_path(vault)
    state_path = service_state_path(vault)
    log_path = service_log_path(vault)
    lock = None
    if state_path.exists():
        try:
            lock = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            lock = {"unreadable": True}
    status = {
        "version": __version__,
        "vault": str(vault.root),
        "control": str(vault.control),
        "schema_version": schema_version(vault.database_path),
        "lock_file": str(lock_path),
        "lock_exists": lock_path.exists(),
        "state_file": str(state_path),
        "state_exists": state_path.exists(),
        "lock": lock,
        "log_file": str(log_path),
        "log_exists": log_path.exists(),
        "log_bytes": log_path.stat().st_size if log_path.exists() else 0,
        "storage": vault.status(),
    }
    if config is not None:
        status["server"] = {
            "host": config.host,
            "port": config.port,
            "allow_lan": config.allow_lan,
            "node_url": config.effective_url,
            "certificate_fingerprint": config.certificate_fingerprint,
            "service_name": config.service_name,
        }
    return status


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _tail_bytes(path: Path, limit: int = DIAGNOSTIC_LOG_TAIL_BYTES) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > limit:
            handle.seek(size - limit)
        return handle.read()


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def create_diagnostic_bundle(vault, config: ServerConfig | None = None, destination: Path | str | None = None) -> dict:
    diagnostics_directory(vault).mkdir(parents=True, exist_ok=True)
    if destination is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        destination_path = diagnostics_directory(vault) / f"psn-drive-diagnostics-{timestamp}.zip"
    else:
        destination_path = Path(destination).expanduser().resolve()
        destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists():
        raise FileExistsError(destination_path)

    manifest = {
        "format": "psn-drive-diagnostics-v1",
        "created_at": utc_now(),
        "version": __version__,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": sys.version.split()[0],
        },
        "contains_secrets": False,
        "excluded": [
            ".psn/master.key",
            ".psn/tls.key",
            ".psn/blobs/",
            "device private keys",
            "access tokens",
        ],
    }
    status = service_status(vault, config)
    files: dict[str, bytes] = {}
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    files["service-status.json"] = json.dumps(status, ensure_ascii=False, indent=2).encode("utf-8")
    if config is not None:
        safe_config = config.to_dict()
        files["server-config-redacted.json"] = json.dumps(safe_config, ensure_ascii=False, indent=2).encode("utf-8")
    metadata = {
        "path": str(vault.database_path),
        "exists": vault.database_path.exists(),
        "bytes": vault.database_path.stat().st_size if vault.database_path.exists() else 0,
        "sha256": _sha256(vault.database_path) if vault.database_path.exists() else None,
        "schema_version": schema_version(vault.database_path),
    }
    files["metadata-summary.json"] = json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8")
    log_path = service_log_path(vault)
    if log_path.exists():
        files["logs/server-tail.log"] = _tail_bytes(log_path)
    readme = (
        "PSN Drive diagnostic bundle.\n"
        "This bundle intentionally excludes master keys, TLS private keys, encrypted blobs, device private keys, and tokens.\n"
    )
    files["README.txt"] = readme.encode("utf-8")

    temporary = destination_path.with_name(f".{destination_path.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in files.items():
                archive.writestr(name, payload)
        os.replace(temporary, destination_path)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": str(destination_path),
        "bytes": destination_path.stat().st_size,
        "sha256": _sha256(destination_path),
        "files": sorted(files),
        "contains_secrets": False,
    }


def prepare_service_runtime(vault) -> dict:
    for directory in (run_directory(vault), logs_directory(vault), diagnostics_directory(vault)):
        directory.mkdir(parents=True, exist_ok=True)
    return {
        "run_directory": str(run_directory(vault)),
        "logs_directory": str(logs_directory(vault)),
        "diagnostics_directory": str(diagnostics_directory(vault)),
        "lock_file": str(service_lock_path(vault)),
        "state_file": str(service_state_path(vault)),
        "log_file": str(service_log_path(vault)),
    }
