import json
import ssl
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .auth import DeviceAuth
from .errors import (
    AuthenticationError,
    AuthorizationError,
    DriveError,
    FileNotFoundInVault,
    PairingError,
    QuotaExceeded,
    RateLimitExceeded,
    UploadConflict,
)
from .server_config import default_config_path, load_server_config
from .service_runtime import (
    create_diagnostic_bundle,
    list_service_events,
    service_preflight,
    service_status,
)
from .vault import DEFAULT_CHUNK_SIZE, Vault, normalize_virtual_path
from .tls import certificate_fingerprint

MAX_JSON_BODY = 1024 * 1024


class RateLimiter:
    def __init__(self):
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: tuple[str, str], limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(events[0] + window_seconds - now) + 1)
                raise RateLimitExceeded("request rate limit exceeded", retry_after)
            events.append(now)


class DriveHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, vault: Vault):
        super().__init__(address, DriveRequestHandler)
        self.vault = vault
        self.auth = DeviceAuth(vault.database_path)
        self.rate_limiter = RateLimiter()


class DriveRequestHandler(BaseHTTPRequestHandler):
    server: DriveHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # The default log intentionally excludes request bodies and Authorization headers.
        super().log_message(format, *args)

    def _json(self, status: int, value: dict | list, extra_headers: dict | None = None) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, header_value in (extra_headers or {}).items():
            self.send_header(name, str(header_value))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_JSON_BODY:
            raise ValueError("JSON body is empty or too large")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _static(self, filename: str, content_type: str) -> None:
        body = (Path(__file__).parent / "web" / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _authorize(self, scope: str) -> dict:
        self._rate_limit("authenticated", 240, 60)
        header = self.headers.get("Authorization", "")
        scheme, separator, token = header.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("missing Bearer access token")
        return self.server.auth.verify_token(token, scope)

    def _rate_limit(self, bucket: str, limit: int, window_seconds: int) -> None:
        self.server.rate_limiter.check((self.client_address[0], bucket), limit, window_seconds)

    def _server_config_or_none(self):
        path = default_config_path(self.server.vault)
        if not path.exists():
            return None
        return load_server_config(path)

    def _console_summary(self) -> dict:
        config = self._server_config_or_none()
        status = service_status(self.server.vault, config)
        events = list_service_events(self.server.vault, 12)
        return {
            "status": status,
            "events": events,
            "config_exists": config is not None,
            "diagnostics_directory": str(self.server.vault.control / "diagnostics"),
        }

    def _handle_error(self, exc: Exception) -> None:
        if isinstance(exc, AuthenticationError):
            status = 401
        elif isinstance(exc, AuthorizationError):
            status = 403
        elif isinstance(exc, (FileNotFoundInVault,)):
            status = 404
        elif isinstance(exc, (UploadConflict, PairingError)):
            status = 409
        elif isinstance(exc, QuotaExceeded):
            status = 507
        elif isinstance(exc, RateLimitExceeded):
            status = 429
        elif isinstance(exc, (DriveError, ValueError, KeyError, TypeError)):
            status = 400
        else:
            status = 500
        message = str(exc) if status != 500 else "internal server error"
        headers = {"Retry-After": exc.retry_after} if isinstance(exc, RateLimitExceeded) else None
        self._json(status, {"error": exc.__class__.__name__, "message": message}, headers)

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path in ("/", "/index.html"):
                self._rate_limit("static", 120, 60)
                self._static("index.html", "text/html; charset=utf-8")
                return
            if path == "/app.js":
                self._rate_limit("static", 120, 60)
                self._static("app.js", "text/javascript; charset=utf-8")
                return
            if path == "/styles.css":
                self._rate_limit("static", 120, 60)
                self._static("styles.css", "text/css; charset=utf-8")
                return
            if path == "/v1/health":
                self._rate_limit("health", 60, 60)
                self._json(200, {"status": "ok", "service": "psn-drive"})
                return
            if path == "/v1/status":
                self._authorize("drive:read")
                self._json(200, self.server.vault.status())
                return
            if path == "/v1/console":
                self._authorize("drive:read")
                self._rate_limit("console", 60, 60)
                self._json(200, self._console_summary())
                return
            if path == "/v1/console/events":
                self._authorize("drive:read")
                self._rate_limit("console", 60, 60)
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["50"])[0])
                self._json(200, list_service_events(self.server.vault, limit))
                return
            if path == "/v1/files":
                self._authorize("drive:read")
                self._json(200, self.server.vault.list_files())
                return
            if path == "/v1/browse":
                self._authorize("drive:read")
                query = parse_qs(parsed.query)
                self._json(200, self.server.vault.browse(query.get("prefix", [""])[0]))
                return
            if path == "/v1/trash":
                self._authorize("drive:read")
                self._json(200, self.server.vault.list_deleted_files())
                return
            if path == "/v1/shares":
                self._authorize("drive:read")
                query = parse_qs(parsed.query)
                include_inactive = query.get("include_inactive", ["false"])[0].lower() in ("1", "true", "yes")
                self._json(200, self.server.vault.list_share_links(include_inactive))
                return
            if path == "/v1/versions":
                self._authorize("drive:read")
                query = parse_qs(parsed.query)
                virtual_path = query.get("path", [None])[0]
                if not virtual_path:
                    raise ValueError("path query parameter is required")
                self._json(200, self.server.vault.list_versions(virtual_path))
                return
            if path == "/v1/download":
                self._authorize("drive:read")
                query = parse_qs(parsed.query)
                virtual_path = query.get("path", [None])[0]
                version_id = query.get("version", [None])[0]
                if not virtual_path:
                    raise ValueError("path query parameter is required")
                info, manifest = self.server.vault.download_manifest(virtual_path, version_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(info["size"]))
                self.send_header("X-PSN-Version", info["version_id"])
                self.send_header("X-Content-SHA256", info["content_hash"])
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in self.server.vault.iter_manifest(manifest):
                    self.wfile.write(chunk)
                self.close_connection = True
                return
            if path.startswith("/s/"):
                self._rate_limit("share-download", 120, 60)
                token = unquote(path.removeprefix("/s/")).strip("/")
                if not token or "/" in token:
                    raise ValueError("invalid share link")
                info, manifest = self.server.vault.shared_download_manifest(token)
                filename = Path(info["virtual_path"]).name or "download"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(info["size"]))
                self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(filename)}")
                self.send_header("X-PSN-Version", info["version_id"])
                self.send_header("X-Content-SHA256", info["content_hash"])
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in self.server.vault.iter_manifest(manifest):
                    self.wfile.write(chunk)
                self.close_connection = True
                return
            if path.startswith("/v1/uploads/"):
                self._authorize("drive:write")
                session_id = unquote(path.removeprefix("/v1/uploads/")).strip("/")
                if not session_id or "/" in session_id:
                    raise ValueError("invalid upload session path")
                self._json(200, self.server.vault.get_upload(session_id))
                return
            self._json(404, {"error": "NotFound", "message": "route not found"})
        except Exception as exc:
            self._handle_error(exc)

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            if path == "/v1/pairings/claim":
                self._rate_limit("pairing", 5, 60)
                body = self._read_json()
                self._json(
                    201,
                    self.server.auth.claim_pairing(body["code"], body["device_name"], body["public_key"]),
                )
                return
            if path == "/v1/auth/challenges":
                self._rate_limit("challenge", 20, 60)
                body = self._read_json()
                self._json(201, self.server.auth.create_challenge(body["device_id"]))
                return
            if path == "/v1/auth/tokens":
                self._rate_limit("token", 20, 60)
                body = self._read_json()
                self._json(
                    201,
                    self.server.auth.exchange_token(body["device_id"], body["challenge_id"], body["signature"]),
                )
                return
            if path == "/v1/console/preflight":
                self._authorize("drive:read")
                self._rate_limit("console", 20, 60)
                config = self._server_config_or_none()
                if config is None:
                    raise ValueError("server config is missing; run server-config-init first")
                self._json(200, service_preflight(self.server.vault, config))
                return
            if path == "/v1/console/diagnostics":
                self._authorize("drive:write")
                self._rate_limit("console-diagnostics", 5, 60)
                self._json(201, create_diagnostic_bundle(self.server.vault, self._server_config_or_none()))
                return
            if path == "/v1/shares":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(
                    201,
                    self.server.vault.create_share_link(
                        body["virtual_path"],
                        int(body.get("ttl_seconds", 7 * 24 * 60 * 60)),
                        body.get("max_downloads"),
                    ),
                )
                return
            if path == "/v1/shares/revoke":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(200, self.server.vault.revoke_share_link(body["id"]))
                return
            if path == "/v1/admin/challenges":
                principal = self._authorize("drive:write")
                self._rate_limit("admin", 10, 60)
                body = self._read_json()
                action = body["action"]
                resource = normalize_virtual_path(body["resource"]) if action in ("file.delete", "file.purge") else body["resource"]
                self._json(
                    201,
                    self.server.auth.create_admin_challenge(
                        principal["device_id"], action, resource
                    ),
                )
                return
            if path == "/v1/admin/tokens":
                self._rate_limit("admin-token", 10, 60)
                body = self._read_json()
                self._json(
                    201,
                    self.server.auth.exchange_admin_token(
                        body["device_id"], body["challenge_id"], body["signature"]
                    ),
                )
                return
            if path == "/v1/uploads":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(
                    201,
                    self.server.vault.create_upload(
                        body["virtual_path"],
                        int(body["expected_size"]),
                        body["idempotency_key"],
                        int(body.get("ttl_seconds", 3600)),
                        int(body.get("chunk_size", DEFAULT_CHUNK_SIZE)),
                    ),
                )
                return
            if path == "/v1/versions/restore":
                self._authorize("drive:write")
                body = self._read_json()
                new_version_id = self.server.vault.restore_version(body["virtual_path"], body["version_id"])
                self._json(200, {"virtual_path": body["virtual_path"], "version_id": new_version_id, "restored": True})
                return
            if path == "/v1/files/move":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(200, self.server.vault.move_file(body["source"], body["destination"]))
                return
            if path == "/v1/directories":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(201, self.server.vault.create_directory(body["virtual_path"]))
                return
            if path == "/v1/files/batch-move":
                self._authorize("drive:write")
                body = self._read_json()
                self._json(200, self.server.vault.move_files(body["moves"]))
                return
            if path == "/v1/trash/restore":
                self._authorize("drive:write")
                body = self._read_json()
                virtual_path = normalize_virtual_path(body["virtual_path"])
                self.server.vault.restore_file(virtual_path)
                self._json(200, {"virtual_path": virtual_path, "restored": True})
                return
            if path == "/v1/trash/purge":
                principal = self._authorize("drive:write")
                body = self._read_json()
                virtual_path = normalize_virtual_path(body["virtual_path"])
                action_token = self.headers.get("X-PSN-Action-Token", "")
                if not action_token:
                    raise AuthorizationError("administrator action token is required")
                self.server.auth.consume_action_token(
                    action_token, principal["device_id"], "file.purge", virtual_path
                )
                self._json(200, self.server.vault.purge_file(virtual_path))
                return
            if path == "/v1/files/delete":
                principal = self._authorize("drive:write")
                body = self._read_json()
                virtual_path = normalize_virtual_path(body["virtual_path"])
                action_token = self.headers.get("X-PSN-Action-Token", "")
                if not action_token:
                    raise AuthorizationError("administrator action token is required")
                self.server.auth.consume_action_token(
                    action_token, principal["device_id"], "file.delete", virtual_path
                )
                self.server.vault.delete_file(virtual_path)
                self._json(200, {"virtual_path": virtual_path, "deleted": True})
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["v1", "uploads"] and parts[3] == "commit":
                self._authorize("drive:write")
                session_id = parts[2]
                self._json(200, self.server.vault.commit_upload(session_id))
                return
            if len(parts) == 4 and parts[:2] == ["v1", "uploads"] and parts[3] == "abort":
                self._authorize("drive:write")
                session_id = parts[2]
                self._json(200, self.server.vault.abort_upload(session_id))
                return
            self._json(404, {"error": "NotFound", "message": "route not found"})
        except Exception as exc:
            self._handle_error(exc)

    def do_PUT(self):
        try:
            path = urlsplit(self.path).path
            parts = path.strip("/").split("/")
            if len(parts) != 5 or parts[:2] != ["v1", "uploads"] or parts[3] != "chunks":
                self._json(404, {"error": "NotFound", "message": "route not found"})
                return
            self._authorize("drive:write")
            self._rate_limit("chunk", 300, 60)
            session_id = parts[2]
            ordinal = int(parts[4])
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > DEFAULT_CHUNK_SIZE:
                raise ValueError("invalid chunk Content-Length")
            plaintext = self.rfile.read(length)
            self._json(200, self.server.vault.upload_chunk(session_id, ordinal, plaintext))
        except Exception as exc:
            self._handle_error(exc)


def configure_tls(server: DriveHTTPServer, cert_path, key_path) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)


def serve(
    vault: Vault,
    host: str = "127.0.0.1",
    port: int = 7780,
    allow_lan: bool = False,
) -> None:
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not allow_lan:
        raise ValueError("non-loopback binding requires --allow-lan")
    cert_path = vault.control / "tls.crt"
    key_path = vault.control / "tls.key"
    if not cert_path.exists() or not key_path.exists():
        raise ValueError("TLS identity is missing; run tls-init first")
    server = DriveHTTPServer((host, port), vault)
    configure_tls(server, cert_path, key_path)
    server.cert_fingerprint = certificate_fingerprint(cert_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
