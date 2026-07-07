import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

from .auth import DeviceAuth
from .device_client import authorize_admin_action, claim_device, login_device
from .device_keys import create_device_key
from .errors import DriveError
from .http_api import serve
from .server_config import (
    default_config_path,
    generate_windows_service_assets,
    health_check,
    init_server_config,
    load_server_config,
    show_server_config,
)
from .service_runtime import (
    ServiceLock,
    cleanup_stale_service_state,
    create_diagnostic_bundle,
    list_service_events,
    prepare_service_runtime,
    service_preflight,
    service_logging,
    service_status,
    stop_service,
)
from .tls import certificate_fingerprint, create_tls_identity
from .sync_client import SyncClient, SyncConfig
from .vault import Vault


SIZE_SUFFIXES = {
    "B": 1,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KIB": 1024,
    "MIB": 1024**2,
    "GIB": 1024**3,
    "TIB": 1024**4,
}


def parse_size(value: str) -> int:
    text = value.strip().upper().replace(" ", "")
    if text in ("NONE", "UNLIMITED"):
        return -1
    for suffix in sorted(SIZE_SUFFIXES, key=len, reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)]
            try:
                result = float(number) * SIZE_SUFFIXES[suffix]
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid size: {value}") from exc
            if result < 0 or not result.is_integer():
                raise argparse.ArgumentTypeError(f"invalid size: {value}")
            return int(result)
    try:
        result = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid size: {value}") from exc
    if result < 0:
        raise argparse.ArgumentTypeError("size cannot be negative")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="psn-drive", description="PSN Drive local vault prototype")
    parser.add_argument("--vault", default=".", help="vault directory (default: current directory)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="initialize a local vault")

    import_parser = subparsers.add_parser("import", help="import or update a file")
    import_parser.add_argument("source")
    import_parser.add_argument("--path", dest="virtual_path", help="path inside the vault")

    list_parser = subparsers.add_parser("list", help="list files")
    list_parser.add_argument("--deleted", action="store_true", help="include deleted files")

    export_parser = subparsers.add_parser("export", help="export a file")
    export_parser.add_argument("virtual_path")
    export_parser.add_argument("destination")
    export_parser.add_argument("--version", dest="version_id", help="export a specific version")

    versions_parser = subparsers.add_parser("versions", help="list file versions")
    versions_parser.add_argument("virtual_path")

    delete_parser = subparsers.add_parser("delete", help="move a file to the logical recycle bin")
    delete_parser.add_argument("virtual_path")

    restore_parser = subparsers.add_parser("restore", help="restore a file from the recycle bin")
    restore_parser.add_argument("virtual_path")

    restore_version_parser = subparsers.add_parser(
        "restore-version", help="make a historical version current by creating a new version"
    )
    restore_version_parser.add_argument("virtual_path")
    restore_version_parser.add_argument("version_id")

    purge_parser = subparsers.add_parser("purge", help="permanently remove a deleted file")
    purge_parser.add_argument("virtual_path")

    quota_parser = subparsers.add_parser("quota", help="set the physical blob quota")
    quota_parser.add_argument("size", type=parse_size, help="bytes, 10GB, 10GiB, or unlimited")

    begin_upload_parser = subparsers.add_parser("begin-upload", help="create a resumable upload session")
    begin_upload_parser.add_argument("virtual_path")
    begin_upload_parser.add_argument("expected_size", type=int)
    begin_upload_parser.add_argument("idempotency_key")
    begin_upload_parser.add_argument("--ttl", type=int, default=3600, help="session lifetime in seconds")
    begin_upload_parser.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024)

    upload_status_parser = subparsers.add_parser("upload-status", help="show resumable upload progress")
    upload_status_parser.add_argument("session_id")

    upload_chunk_parser = subparsers.add_parser("upload-chunk", help="upload one plaintext chunk file")
    upload_chunk_parser.add_argument("session_id")
    upload_chunk_parser.add_argument("ordinal", type=int)
    upload_chunk_parser.add_argument("source")

    commit_upload_parser = subparsers.add_parser("commit-upload", help="atomically publish an upload")
    commit_upload_parser.add_argument("session_id")

    abort_upload_parser = subparsers.add_parser("abort-upload", help="abort an upload session")
    abort_upload_parser.add_argument("session_id")

    upload_file_parser = subparsers.add_parser("upload-file", help="resumably upload and commit a local file")
    upload_file_parser.add_argument("source")
    upload_file_parser.add_argument("--path", dest="virtual_path", required=True)
    upload_file_parser.add_argument("--key", dest="idempotency_key", required=True)
    upload_file_parser.add_argument("--ttl", type=int, default=3600)
    upload_file_parser.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024)

    subparsers.add_parser("status", help="show storage statistics")
    subparsers.add_parser("verify", help="decrypt and verify all referenced chunks")
    subparsers.add_parser("gc", help="remove unreferenced encrypted chunks")
    subparsers.add_parser("cleanup-uploads", help="expire old sessions and remove orphan blobs")

    pairing_parser = subparsers.add_parser("pairing-create", help="create a one-time device pairing code")
    pairing_parser.add_argument("--ttl", type=int, default=300)
    pairing_parser.add_argument("--url", help="HTTPS node URL to include in a QR-compatible pairing URI")
    subparsers.add_parser("devices", help="list registered devices")
    revoke_parser = subparsers.add_parser("device-revoke", help="revoke a device and all of its tokens")
    revoke_parser.add_argument("device_id")

    keygen_parser = subparsers.add_parser("device-keygen", help="create a local Ed25519 device key")
    keygen_parser.add_argument("key_file")
    claim_parser = subparsers.add_parser("device-claim", help="claim a pairing code from a local API")
    claim_parser.add_argument("url")
    claim_parser.add_argument("fingerprint")
    claim_parser.add_argument("code")
    claim_parser.add_argument("name")
    claim_parser.add_argument("key_file")
    login_parser = subparsers.add_parser("device-login", help="sign a challenge and obtain a short token")
    login_parser.add_argument("url")
    login_parser.add_argument("fingerprint")
    login_parser.add_argument("device_id")
    login_parser.add_argument("key_file")

    admin_parser = subparsers.add_parser("admin-authorize", help="sign a one-time administrator action")
    admin_parser.add_argument("url")
    admin_parser.add_argument("fingerprint")
    admin_parser.add_argument("device_id")
    admin_parser.add_argument("key_file")
    admin_parser.add_argument("action", choices=["file.delete", "file.purge"])
    admin_parser.add_argument("resource")

    serve_parser = subparsers.add_parser("serve", help="serve the authenticated loopback HTTP API")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=7780)
    serve_parser.add_argument("--allow-lan", action="store_true")

    tls_parser = subparsers.add_parser("tls-init", help="create the node self-signed TLS identity")
    tls_parser.add_argument("--san", action="append", default=[], help="additional DNS name or IP address")

    sync_init_parser = subparsers.add_parser("sync-init", help="create a Windows folder sync configuration")
    sync_init_parser.add_argument("config_file")
    sync_init_parser.add_argument("local_root")
    sync_init_parser.add_argument("node_url")
    sync_init_parser.add_argument("fingerprint")
    sync_init_parser.add_argument("device_id")
    sync_init_parser.add_argument("key_file")
    sync_init_parser.add_argument("--remote-prefix", default="computers/windows")

    sync_run_parser = subparsers.add_parser("sync-run", help="run one folder synchronization pass")
    sync_run_parser.add_argument("config_file")
    sync_run_parser.add_argument("--full-scan", action="store_true")

    sync_status_parser = subparsers.add_parser("sync-status", help="show local synchronization state")
    sync_status_parser.add_argument("config_file")

    sync_watch_parser = subparsers.add_parser("sync-watch", help="periodically run folder synchronization")
    sync_watch_parser.add_argument("config_file")
    sync_watch_parser.add_argument("--interval", type=int, default=300, help="seconds between runs")
    sync_watch_parser.add_argument("--max-runs", type=int, default=0, help="stop after N runs; 0 means forever")

    directory_parser = subparsers.add_parser("directory-create", help="create an explicit empty directory")
    directory_parser.add_argument("virtual_path")
    batch_parser = subparsers.add_parser("batch-move", help="atomically move files from a JSON mapping list")
    batch_parser.add_argument("json_file")
    retention_set = subparsers.add_parser("retention-set", help="set trash retention days")
    retention_set.add_argument("days", help="1-3650 or disabled")
    retention_run = subparsers.add_parser("retention-run", help="preview or apply expired trash cleanup")
    retention_run.add_argument("--apply", action="store_true")
    subparsers.add_parser("metadata-backup", help="create a checksummed SQLite metadata backup")
    subparsers.add_parser("metadata-backups", help="list metadata backups")
    metadata_restore = subparsers.add_parser("metadata-restore", help="restore a verified metadata backup")
    metadata_restore.add_argument("backup_file")
    disaster_backup = subparsers.add_parser("disaster-backup", help="create a full vault disaster recovery archive")
    disaster_backup.add_argument("--destination", help="output .tar file; defaults to .psn/disaster-backups")
    disaster_backup.add_argument("--label", default="manual", help="human-readable backup label")
    subparsers.add_parser("disaster-backups", help="list full disaster recovery archives")
    disaster_restore = subparsers.add_parser("disaster-restore", help="restore a full disaster recovery archive")
    disaster_restore.add_argument("backup_file")
    disaster_restore.add_argument("--destination", default=None, help="vault root to restore into; defaults to --vault")
    disaster_restore.add_argument("--force", action="store_true", help="replace an existing .psn after keeping a safety copy")

    server_init = subparsers.add_parser("server-config-init", help="create a server runtime config and TLS identity")
    server_init.add_argument("--host", default="127.0.0.1")
    server_init.add_argument("--port", type=int, default=7780)
    server_init.add_argument("--allow-lan", action="store_true")
    server_init.add_argument("--url", dest="node_url", help="public/local HTTPS URL advertised to devices")
    server_init.add_argument("--service-name", default="PSNDrive")
    server_init.add_argument("--san", action="append", default=[], help="additional TLS DNS name or IP address")

    server_show = subparsers.add_parser("server-config-show", help="show the server runtime config")
    server_show.add_argument("--config", help="server config file; defaults to .psn/server.json")

    server_run = subparsers.add_parser("server-run", help="run the HTTPS server from server.json")
    server_run.add_argument("--config", help="server config file; defaults to .psn/server.json")
    server_run.add_argument("--foreground", action="store_true", help="keep logs on the console instead of .psn/logs/server.log")

    server_health = subparsers.add_parser("server-health", help="check server /v1/health with certificate pinning")
    server_health.add_argument("--config", help="server config file; defaults to .psn/server.json")

    server_status = subparsers.add_parser("server-status", help="show service runtime status")
    server_status.add_argument("--config", help="server config file; defaults to .psn/server.json")

    server_preflight = subparsers.add_parser("server-preflight", help="check service config, TLS, paths and port before start")
    server_preflight.add_argument("--config", help="server config file; defaults to .psn/server.json")

    server_stop = subparsers.add_parser("server-stop", help="stop a local server-run process using the service state pid")
    server_stop.add_argument("--timeout", type=int, default=10, help="seconds to wait for shutdown")
    server_stop.add_argument("--force", action="store_true", help="try a stronger termination after timeout")
    server_stop.add_argument("--cleanup-stale", action="store_true", help="remove stale state when no process is running")

    diagnostics = subparsers.add_parser("server-diagnostics", help="create a redacted service diagnostic bundle")
    diagnostics.add_argument("--config", help="server config file; defaults to .psn/server.json")
    diagnostics.add_argument("--destination", help="output .zip file; defaults to .psn/diagnostics")

    events = subparsers.add_parser("server-events", help="show recent structured service lifecycle events")
    events.add_argument("--limit", type=int, default=50)

    service_scripts = subparsers.add_parser("windows-service-scripts", help="generate Windows service/task scripts")
    service_scripts.add_argument("--config", help="server config file; defaults to .psn/server.json")
    service_scripts.add_argument("--output", help="output directory; defaults to .psn/service/windows")
    service_scripts.add_argument("--python", dest="python_executable", help="python.exe used by generated scripts")
    return parser


def print_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            vault = Vault.create(args.vault)
            print_json({"vault": str(vault.root), "initialized": True})
            return 0

        if args.command == "device-keygen":
            public_key = create_device_key(Path(args.key_file))
            print_json({"key_file": str(Path(args.key_file).resolve()), "public_key": public_key})
            return 0
        if args.command == "device-claim":
            print_json(claim_device(args.url, args.fingerprint, args.code, args.name, Path(args.key_file)))
            return 0
        if args.command == "device-login":
            print_json(login_device(args.url, args.fingerprint, args.device_id, Path(args.key_file)))
            return 0
        if args.command == "admin-authorize":
            print_json(
                authorize_admin_action(
                    args.url,
                    args.fingerprint,
                    args.device_id,
                    Path(args.key_file),
                    args.action,
                    args.resource,
                )
            )
            return 0
        if args.command == "sync-init":
            config = SyncConfig(
                node_url=args.node_url,
                certificate_fingerprint=args.fingerprint,
                device_id=args.device_id,
                key_file=str(Path(args.key_file).expanduser().resolve()),
                local_root=str(Path(args.local_root).expanduser().resolve()),
                remote_prefix=args.remote_prefix,
            )
            config.validate()
            config.save(args.config_file)
            print_json({"config_file": str(Path(args.config_file).resolve()), "created": True})
            return 0
        if args.command in ("sync-run", "sync-status", "sync-watch"):
            client = SyncClient(SyncConfig.load(args.config_file))
            try:
                if args.command == "sync-run":
                    result = client.run(args.full_scan)
                    print_json(result)
                    return 1 if result["failed"] else 0
                if args.command == "sync-status":
                    print_json(client.status())
                    return 0
                if args.interval < 10:
                    raise ValueError("sync-watch interval must be at least 10 seconds")
                if args.max_runs < 0:
                    raise ValueError("max-runs cannot be negative")
                completed = 0
                try:
                    with client.lock():
                        while True:
                            print_json(client.run(acquire_lock=False))
                            completed += 1
                            if args.max_runs and completed >= args.max_runs:
                                return 0
                            time.sleep(args.interval)
                except KeyboardInterrupt:
                    return 0
            finally:
                client.close()

        if args.command == "disaster-restore":
            print_json(Vault.restore_disaster(args.backup_file, args.destination or args.vault, args.force))
            return 0

        if args.command == "server-run":
            config_path = Path(args.config).expanduser().resolve() if args.config else None
            if config_path is None:
                vault_for_default = Vault(args.vault)
                config_path = default_config_path(vault_for_default)
            config = load_server_config(config_path)
            vault = Vault(config.vault)
            runtime = prepare_service_runtime(vault)
            with ServiceLock(vault):
                if args.foreground:
                    print(f"PSN Drive API listening on {config.effective_url}", file=sys.stderr)
                    print(f"Certificate SHA-256: {config.certificate_fingerprint}", file=sys.stderr)
                    print(f"Log file: {runtime['log_file']}", file=sys.stderr)
                    serve(vault, config.host, config.port, config.allow_lan)
                else:
                    with service_logging(vault):
                        print(f"PSN Drive API listening on {config.effective_url}", file=sys.stderr)
                        print(f"Certificate SHA-256: {config.certificate_fingerprint}", file=sys.stderr)
                        serve(vault, config.host, config.port, config.allow_lan)
            return 0

        vault = Vault(args.vault)
        auth = DeviceAuth(vault.database_path)
        if args.command == "import":
            print_json(vault.import_file(args.source, args.virtual_path).__dict__)
        elif args.command == "list":
            print_json(vault.list_files(args.deleted))
        elif args.command == "versions":
            print_json(vault.list_versions(args.virtual_path))
        elif args.command == "export":
            print_json(vault.export_file(args.virtual_path, args.destination, args.version_id))
        elif args.command == "delete":
            vault.delete_file(args.virtual_path)
            print_json({"path": args.virtual_path, "deleted": True})
        elif args.command == "restore":
            vault.restore_file(args.virtual_path)
            print_json({"path": args.virtual_path, "restored": True})
        elif args.command == "restore-version":
            version_id = vault.restore_version(args.virtual_path, args.version_id)
            print_json({"path": args.virtual_path, "version_id": version_id, "restored": True})
        elif args.command == "purge":
            print_json(vault.purge_file(args.virtual_path))
        elif args.command == "quota":
            vault.set_quota(None if args.size == -1 else args.size)
            print_json({"quota_bytes": vault.get_quota()})
        elif args.command == "begin-upload":
            print_json(
                vault.create_upload(
                    args.virtual_path,
                    args.expected_size,
                    args.idempotency_key,
                    args.ttl,
                    args.chunk_size,
                )
            )
        elif args.command == "upload-status":
            print_json(vault.get_upload(args.session_id))
        elif args.command == "upload-chunk":
            print_json(vault.upload_chunk(args.session_id, args.ordinal, Path(args.source).read_bytes()))
        elif args.command == "commit-upload":
            print_json(vault.commit_upload(args.session_id))
        elif args.command == "abort-upload":
            print_json(vault.abort_upload(args.session_id))
        elif args.command == "upload-file":
            source = Path(args.source)
            if not source.is_file():
                raise FileNotFoundError(source)
            session = vault.create_upload(
                args.virtual_path,
                source.stat().st_size,
                args.idempotency_key,
                args.ttl,
                args.chunk_size,
            )
            if session["state"] == "committed":
                print_json(vault.commit_upload(session["id"]))
            else:
                uploaded = {item["ordinal"] for item in session["uploaded_chunks"]}
                with source.open("rb") as handle:
                    ordinal = 0
                    while True:
                        chunk = handle.read(args.chunk_size)
                        if not chunk:
                            break
                        if ordinal not in uploaded:
                            vault.upload_chunk(session["id"], ordinal, chunk)
                        ordinal += 1
                print_json(vault.commit_upload(session["id"]))
        elif args.command == "status":
            print_json(vault.status())
        elif args.command == "verify":
            print_json(vault.verify())
        elif args.command == "gc":
            print_json(vault.collect_garbage())
        elif args.command == "cleanup-uploads":
            print_json(vault.cleanup_uploads())
        elif args.command == "pairing-create":
            pairing = auth.create_pairing(args.ttl)
            if args.url:
                cert_path = vault.control / "tls.crt"
                if not cert_path.exists():
                    raise ValueError("TLS identity is missing; run tls-init first")
                fingerprint = certificate_fingerprint(cert_path)
                pairing["node_url"] = args.url
                pairing["certificate_fingerprint"] = fingerprint
                pairing["pairing_uri"] = "psn://pair?" + urlencode(
                    {"url": args.url, "code": pairing["code"], "fingerprint": fingerprint}
                )
            print_json(pairing)
        elif args.command == "devices":
            print_json(auth.list_devices())
        elif args.command == "device-revoke":
            auth.revoke_device(args.device_id)
            print_json({"device_id": args.device_id, "revoked": True})
        elif args.command == "tls-init":
            hosts = ["localhost", "127.0.0.1", *args.san]
            fingerprint = create_tls_identity(
                vault.control / "tls.crt", vault.control / "tls.key", hosts
            )
            print_json({"certificate": str(vault.control / "tls.crt"), "fingerprint": fingerprint, "san": hosts})
        elif args.command == "serve":
            cert_path = vault.control / "tls.crt"
            if not cert_path.exists():
                raise ValueError("TLS identity is missing; run tls-init first")
            fingerprint = certificate_fingerprint(cert_path)
            print(f"PSN Drive API listening on https://{args.host}:{args.port}", file=sys.stderr)
            print(f"Certificate SHA-256: {fingerprint}", file=sys.stderr)
            serve(vault, args.host, args.port, args.allow_lan)
        elif args.command == "directory-create":
            print_json(vault.create_directory(args.virtual_path))
        elif args.command == "batch-move":
            moves = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
            if not isinstance(moves, list):
                raise ValueError("batch move JSON must be a list")
            print_json(vault.move_files(moves))
        elif args.command == "retention-set":
            days = None if args.days.lower() == "disabled" else int(args.days)
            vault.set_trash_retention(days)
            print_json({"trash_retention_days": vault.get_trash_retention()})
        elif args.command == "retention-run":
            print_json(vault.run_trash_retention(args.apply))
        elif args.command == "metadata-backup":
            print_json(vault.backup_metadata())
        elif args.command == "metadata-backups":
            print_json(vault.list_metadata_backups())
        elif args.command == "metadata-restore":
            print_json(vault.restore_metadata(args.backup_file))
        elif args.command == "disaster-backup":
            print_json(vault.backup_disaster(args.destination, args.label))
        elif args.command == "disaster-backups":
            print_json(vault.list_disaster_backups())
        elif args.command == "server-config-init":
            print_json(
                init_server_config(
                    vault,
                    args.host,
                    args.port,
                    args.allow_lan,
                    args.node_url,
                    args.service_name,
                    args.san,
                )
            )
        elif args.command == "server-config-show":
            print_json(show_server_config(vault, args.config))
        elif args.command == "server-health":
            config_path = Path(args.config).expanduser().resolve() if args.config else default_config_path(vault)
            print_json(health_check(load_server_config(config_path)))
        elif args.command == "server-status":
            config_path = Path(args.config).expanduser().resolve() if args.config else default_config_path(vault)
            print_json(service_status(vault, load_server_config(config_path)))
        elif args.command == "server-preflight":
            config_path = Path(args.config).expanduser().resolve() if args.config else default_config_path(vault)
            result = service_preflight(vault, load_server_config(config_path))
            print_json(result)
            return 0 if result["ok"] else 1
        elif args.command == "server-stop":
            if args.cleanup_stale:
                print_json(cleanup_stale_service_state(vault))
            else:
                print_json(stop_service(vault, args.timeout, args.force))
        elif args.command == "server-diagnostics":
            config_path = Path(args.config).expanduser().resolve() if args.config else default_config_path(vault)
            print_json(create_diagnostic_bundle(vault, load_server_config(config_path), args.destination))
        elif args.command == "server-events":
            print_json(list_service_events(vault, args.limit))
        elif args.command == "windows-service-scripts":
            config_path = Path(args.config).expanduser().resolve() if args.config else default_config_path(vault)
            output = args.output or (vault.control / "service" / "windows")
            print_json(generate_windows_service_assets(config_path, output, args.python_executable))
        return 0
    except (DriveError, FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
