import contextlib
import hashlib
import json
import os
import platform
import signal
import socket
import sys
import time
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
EVENT_LOG_FILE = "service-events.jsonl"
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


def service_event_log_path(vault) -> Path:
    return logs_directory(vault) / EVENT_LOG_FILE


def append_service_event(vault, event_type: str, **fields) -> dict:
    path = service_event_log_path(vault)
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "at": utc_now(),
        "event": event_type,
        "version": __version__,
        **fields,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    return event


def list_service_events(vault, limit: int = 50) -> list[dict]:
    if limit <= 0:
        raise ValueError("event limit must be positive")
    path = service_event_log_path(vault)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            events.append({"event": "unreadable", "raw": line})
    return events


def process_is_running(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


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
        append_service_event(self.vault, "service.lock_acquired", pid=os.getpid())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        service_state_path(self.vault).unlink(missing_ok=True)
        append_service_event(self.vault, "service.lock_released", pid=os.getpid())
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
            append_service_event(vault, "service.starting", pid=os.getpid())
            print(json.dumps({"event": "service.starting", "at": utc_now(), "version": __version__}, ensure_ascii=False), flush=True)
            yield path
            print(json.dumps({"event": "service.stopped", "at": utc_now()}, ensure_ascii=False), flush=True)
            append_service_event(vault, "service.stopped", pid=os.getpid())
        except Exception as exc:
            print(
                json.dumps(
                    {"event": "service.failed", "at": utc_now(), "error": exc.__class__.__name__, "message": str(exc)},
                    ensure_ascii=False,
                ),
                flush=True,
            )
            append_service_event(vault, "service.failed", error=exc.__class__.__name__, message=str(exc))
            raise
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr


def service_status(vault, config: ServerConfig | None = None) -> dict:
    lock_path = service_lock_path(vault)
    state_path = service_state_path(vault)
    log_path = service_log_path(vault)
    event_log_path = service_event_log_path(vault)
    lock = None
    if state_path.exists():
        try:
            lock = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            lock = {"unreadable": True}
    pid = lock.get("pid") if isinstance(lock, dict) else None
    running = process_is_running(pid) if isinstance(pid, int) else False
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
        "process_running": running,
        "stale_state": bool(state_path.exists() and lock and not running),
        "log_file": str(log_path),
        "log_exists": log_path.exists(),
        "log_bytes": log_path.stat().st_size if log_path.exists() else 0,
        "event_log_file": str(event_log_path),
        "event_log_exists": event_log_path.exists(),
        "event_log_bytes": event_log_path.stat().st_size if event_log_path.exists() else 0,
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


def _check_port_available(host: str, port: int) -> dict:
    with socket.socket(socket.AF_INET6 if ":" in host and host != "127.0.0.1" else socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            return {"name": "port_available", "ok": False, "message": str(exc)}
    return {"name": "port_available", "ok": True, "message": f"{host}:{port} is available"}


def service_preflight(vault, config: ServerConfig) -> dict:
    prepare_service_runtime(vault)
    checks = []
    config_error = None
    try:
        config.validate()
    except Exception as exc:
        config_error = str(exc)
    checks.append({"name": "config_valid", "ok": config_error is None, "message": config_error or "server config is valid"})
    checks.append({
        "name": "vault_initialized",
        "ok": vault.key_path.exists() and vault.database_path.exists(),
        "message": "vault key and metadata database exist",
    })
    cert_path = vault.control / "tls.crt"
    key_path = vault.control / "tls.key"
    checks.append({
        "name": "tls_identity",
        "ok": cert_path.exists() and key_path.exists(),
        "message": "TLS certificate and private key exist" if cert_path.exists() and key_path.exists() else "TLS identity is missing",
    })
    for directory_name, directory in (
        ("run_directory_writable", run_directory(vault)),
        ("logs_directory_writable", logs_directory(vault)),
        ("diagnostics_directory_writable", diagnostics_directory(vault)),
    ):
        marker = directory / ".write-test"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            marker.write_text("ok", encoding="utf-8")
            marker.unlink(missing_ok=True)
            checks.append({"name": directory_name, "ok": True, "message": str(directory)})
        except OSError as exc:
            checks.append({"name": directory_name, "ok": False, "message": str(exc)})
    status = service_status(vault, config)
    checks.append({
        "name": "service_not_running",
        "ok": not status["process_running"],
        "message": "service appears stopped" if not status["process_running"] else f"service pid {status['lock'].get('pid')} is running",
    })
    if not status["process_running"]:
        checks.append(_check_port_available(config.host, config.port))
    passed = all(item["ok"] for item in checks)
    result = {"ok": passed, "checks": checks, "status": status}
    append_service_event(vault, "service.preflight", ok=passed, failed_checks=[item["name"] for item in checks if not item["ok"]])
    return result


def cleanup_stale_service_state(vault) -> dict:
    status = service_status(vault)
    removed = False
    if status["stale_state"]:
        service_state_path(vault).unlink(missing_ok=True)
        removed = True
    append_service_event(vault, "service.cleanup_stale_state", removed=removed)
    return {"removed": removed, "state_file": str(service_state_path(vault))}


def stop_service(vault, timeout_seconds: int = 10, force: bool = False) -> dict:
    status = service_status(vault)
    state = status.get("lock") or {}
    pid = state.get("pid") if isinstance(state, dict) else None
    if not isinstance(pid, int) or not status["state_exists"]:
        result = {"stopped": False, "reason": "not_running", "message": "service state file is missing"}
        append_service_event(vault, "service.stop", **result)
        return result
    if not process_is_running(pid):
        service_state_path(vault).unlink(missing_ok=True)
        result = {"stopped": False, "reason": "stale_state_removed", "pid": pid}
        append_service_event(vault, "service.stop", **result)
        return result
    if pid == os.getpid():
        raise ValueError("refusing to stop the current process")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        raise ValueError(f"failed to signal service process {pid}: {exc}") from exc
    deadline = time.monotonic() + max(timeout_seconds, 0)
    while time.monotonic() < deadline:
        if not process_is_running(pid):
            service_state_path(vault).unlink(missing_ok=True)
            result = {"stopped": True, "pid": pid, "forced": False}
            append_service_event(vault, "service.stop", **result)
            return result
        time.sleep(0.1)
    if force:
        if os.name == "nt":
            os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not process_is_running(pid):
                service_state_path(vault).unlink(missing_ok=True)
                result = {"stopped": True, "pid": pid, "forced": True}
                append_service_event(vault, "service.stop", **result)
                return result
            time.sleep(0.1)
    result = {"stopped": False, "reason": "timeout", "pid": pid}
    append_service_event(vault, "service.stop", **result)
    return result


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
    event_log = service_event_log_path(vault)
    if event_log.exists():
        files["logs/service-events-tail.jsonl"] = _tail_bytes(event_log)
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
    result = {
        "path": str(destination_path),
        "bytes": destination_path.stat().st_size,
        "sha256": _sha256(destination_path),
        "files": sorted(files),
        "contains_secrets": False,
    }
    append_service_event(vault, "service.diagnostics_created", path=str(destination_path), bytes=result["bytes"])
    return result


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
        "event_log_file": str(service_event_log_path(vault)),
    }
