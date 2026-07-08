import os
import sys
import tempfile
import base64
import json
import subprocess
import threading
import unittest
import ssl
import tarfile
import shutil
import uuid
import zipfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from psn_drive.auth import DeviceAuth, admin_challenge_message, challenge_message
from psn_drive.errors import (
    AuthenticationError,
    FileNotFoundInVault,
    IntegrityError,
    InvalidVirtualPath,
    QuotaExceeded,
    RateLimitExceeded,
    UploadConflict,
    UploadSessionExpired,
    SyncAlreadyRunning,
)
from psn_drive.http_api import DriveHTTPServer, RateLimiter, configure_tls
from psn_drive.device_client import pinned_request
from psn_drive.errors import CertificatePinError
from psn_drive.tls import certificate_fingerprint, create_tls_identity
from psn_drive.sync_client import SyncClient, SyncConfig
from psn_drive.sync_client import generate_windows_sync_assets
from psn_drive.sync_lock import SyncLock
from psn_drive.server_config import (
    generate_windows_service_assets,
    health_check,
    init_server_config,
    load_server_config,
)
from psn_drive.service_runtime import (
    ServiceLock,
    append_service_event,
    cleanup_stale_service_state,
    create_diagnostic_bundle,
    list_service_events,
    prepare_service_runtime,
    process_is_running,
    service_preflight,
    service_log_path,
    service_logging,
    service_event_log_path,
    service_state_path,
    service_status,
    stop_service,
)
from psn_drive.vault import Vault, normalize_virtual_path


class VaultTests(unittest.TestCase):
    def setUp(self):
        test_temp_root = Path.cwd() / "test-tmp"
        test_temp_root.mkdir(exist_ok=True)
        self.temporary = test_temp_root / f"psn-drive-test-{uuid.uuid4().hex}"
        self.temporary.mkdir()
        self.root = self.temporary
        self.vault = Vault.create(self.root / "vault")

    def tearDown(self):
        shutil.rmtree(self.temporary, ignore_errors=True)

    def make_file(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def test_import_export_and_verify(self):
        content = os.urandom(1024 * 1024) + b"tail"
        source = self.make_file("photo.bin", content)
        result = self.vault.import_file(source, "photos/2026/photo.bin", chunk_size=128 * 1024)
        self.assertFalse(result.unchanged)
        self.assertGreater(result.chunks, 1)

        destination = self.root / "restored.bin"
        self.vault.export_file("photos/2026/photo.bin", destination)
        self.assertEqual(destination.read_bytes(), content)
        self.assertEqual(self.vault.verify()["checked_bytes"], len(content))

    def test_duplicate_content_is_deduplicated(self):
        source = self.make_file("same.bin", b"same content" * 1000)
        first = self.vault.import_file(source, "a.bin", chunk_size=1024)
        second = self.vault.import_file(source, "b.bin", chunk_size=1024)
        self.assertGreater(first.new_chunks, 0)
        self.assertEqual(second.new_chunks, 0)
        status = self.vault.status()
        self.assertEqual(status["live_files"], 2)
        self.assertEqual(status["versions"], 2)

    def test_unchanged_import_does_not_create_version(self):
        source = self.make_file("stable.txt", b"stable")
        first = self.vault.import_file(source, "stable.txt")
        second = self.vault.import_file(source, "stable.txt")
        self.assertEqual(first.version_id, second.version_id)
        self.assertTrue(second.unchanged)
        self.assertEqual(self.vault.status()["versions"], 1)

    def test_update_preserves_old_version(self):
        source = self.make_file("note.txt", b"one")
        first = self.vault.import_file(source, "note.txt")
        source.write_bytes(b"two")
        second = self.vault.import_file(source, "note.txt")
        self.assertNotEqual(first.version_id, second.version_id)
        self.assertEqual(self.vault.status()["versions"], 2)

        versions = self.vault.list_versions("note.txt")
        self.assertEqual(len(versions), 2)
        old_version = next(item for item in versions if item["id"] == first.version_id)
        self.assertEqual(old_version["is_current"], 0)

        restored_path = self.root / "old-note.txt"
        self.vault.export_file("note.txt", restored_path, first.version_id)
        self.assertEqual(restored_path.read_bytes(), b"one")

        restored_version = self.vault.restore_version("note.txt", first.version_id)
        self.assertNotEqual(restored_version, first.version_id)
        current_path = self.root / "current-note.txt"
        self.vault.export_file("note.txt", current_path)
        self.assertEqual(current_path.read_bytes(), b"one")
        self.assertEqual(self.vault.status()["versions"], 3)

    def test_delete_hides_file(self):
        source = self.make_file("delete.txt", b"delete me")
        self.vault.import_file(source, "delete.txt")
        self.vault.delete_file("delete.txt")
        self.assertEqual(self.vault.list_files(), [])
        self.assertEqual(len(self.vault.list_files(include_deleted=True)), 1)
        with self.assertRaises(FileNotFoundInVault):
            self.vault.export_file("delete.txt", self.root / "nope")
        self.vault.restore_file("delete.txt")
        self.assertEqual(len(self.vault.list_files()), 1)

    def test_browse_move_and_trash_lifecycle(self):
        source = self.make_file("browse.txt", b"browse")
        self.vault.import_file(source, "documents/work/report.txt")
        self.vault.import_file(source, "documents/readme.txt")
        root = self.vault.browse()
        self.assertEqual(root["directories"][0]["path"], "documents")
        documents = self.vault.browse("documents")
        self.assertEqual(documents["directories"][0]["path"], "documents/work")
        self.assertEqual(documents["files"][0]["virtual_path"], "documents/readme.txt")
        moved = self.vault.move_file("documents/readme.txt", "archive/readme.txt")
        self.assertTrue(moved["moved"])
        self.vault.delete_file("archive/readme.txt")
        trash = self.vault.list_deleted_files()
        self.assertEqual(trash[0]["virtual_path"], "archive/readme.txt")

    def test_empty_directories_and_atomic_batch_swap(self):
        self.vault.create_directory("empty/nested")
        self.assertEqual(self.vault.browse("empty")["directories"][0]["path"], "empty/nested")
        first = self.make_file("first.txt", b"first")
        second = self.make_file("second.txt", b"second")
        self.vault.import_file(first, "swap/a.txt")
        self.vault.import_file(second, "swap/b.txt")
        result = self.vault.move_files([
            {"source":"swap/a.txt", "destination":"swap/b.txt"},
            {"source":"swap/b.txt", "destination":"swap/a.txt"},
        ])
        self.assertEqual(result["moved"], 2)
        restored = self.root / "swapped.txt"
        self.vault.export_file("swap/a.txt", restored)
        self.assertEqual(restored.read_bytes(), b"second")

    def test_metadata_backup_restore_and_retention_preview(self):
        import sqlite3

        first = self.make_file("backup-one.txt", b"one")
        second = self.make_file("backup-two.txt", b"two")
        self.vault.import_file(first, "one.txt")
        backup = self.vault.backup_metadata()
        self.assertTrue(Path(backup["path"]).is_file())
        self.vault.import_file(second, "two.txt")
        self.vault.restore_metadata(backup["path"])
        self.assertEqual([item["virtual_path"] for item in self.vault.list_files()], ["one.txt"])
        self.assertGreaterEqual(len(self.vault.list_metadata_backups()), 2)

        self.vault.delete_file("one.txt")
        connection = sqlite3.connect(self.vault.database_path)
        connection.execute("UPDATE files SET deleted_at = '2000-01-01T00:00:00+00:00' WHERE virtual_path = 'one.txt'")
        connection.commit()
        connection.close()
        self.vault.set_trash_retention(30)
        preview = self.vault.run_trash_retention(False)
        self.assertEqual(preview["candidate_count"], 1)
        self.assertEqual(len(self.vault.list_deleted_files()), 1)
        applied = self.vault.run_trash_retention(True)
        self.assertTrue(applied["applied"])
        self.assertEqual(self.vault.list_deleted_files(), [])

    def test_disaster_backup_restore_and_force_safety_copy(self):
        source = self.make_file("family-photo.jpg", b"photo-bytes" * 1000)
        self.vault.import_file(source, "photos/family/photo.jpg", chunk_size=128)
        backup = self.vault.backup_disaster(label="unit-test")
        backup_path = Path(backup["path"])
        self.assertTrue(backup_path.is_file())
        self.assertTrue(Path(backup["manifest_path"]).is_file())
        self.assertEqual(self.vault.list_disaster_backups()[0]["path"], str(backup_path))

        restored_root = self.root / "restored-vault"
        result = Vault.restore_disaster(backup_path, restored_root)
        self.assertTrue(result["restored"])
        restored_vault = Vault(restored_root)
        restored = self.root / "restored-photo.jpg"
        restored_vault.export_file("photos/family/photo.jpg", restored)
        self.assertEqual(restored.read_bytes(), source.read_bytes())

        replacement = self.root / "replacement-vault"
        existing = Vault.create(replacement)
        existing.import_file(self.make_file("old.txt", b"old"), "old.txt")
        with self.assertRaises(FileExistsError):
            Vault.restore_disaster(backup_path, replacement)
        forced = Vault.restore_disaster(backup_path, replacement, force=True)
        self.assertIsNotNone(forced["safety_backup"])
        self.assertTrue(Path(forced["safety_backup"]).is_dir())
        replaced_vault = Vault(replacement)
        replaced_vault.export_file("photos/family/photo.jpg", self.root / "forced-photo.jpg")

    def test_disaster_restore_rejects_corrupt_archive(self):
        source = self.make_file("important.bin", b"important")
        self.vault.import_file(source, "important.bin")
        backup = Path(self.vault.backup_disaster()["path"])
        extracted = self.root / "corrupt-source"
        extracted.mkdir()
        with tarfile.open(backup, "r") as archive:
            archive.extractall(extracted, filter="data")
        key_path = extracted / ".psn" / "master.key"
        key_path.write_bytes(key_path.read_bytes()[:-1] + b"x")
        corrupt = self.root / "corrupt.tar"
        with tarfile.open(corrupt, "w") as archive:
            archive.add(extracted / "psn-disaster-manifest.json", arcname="psn-disaster-manifest.json")
            for path in sorted((extracted / ".psn").rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(extracted).as_posix())
        with self.assertRaises((IntegrityError, ValueError, tarfile.TarError, EOFError)):
            Vault.restore_disaster(corrupt, self.root / "corrupt-restore")

    def test_purge_reclaims_only_unshared_chunks(self):
        source = self.make_file("shared.txt", b"shared content")
        self.vault.import_file(source, "first.txt")
        self.vault.import_file(source, "second.txt")
        self.vault.delete_file("first.txt")
        first_purge = self.vault.purge_file("first.txt")
        self.assertEqual(first_purge["deleted_chunks"], 0)
        self.assertEqual(self.vault.status()["chunks"], 1)

        self.vault.delete_file("second.txt")
        second_purge = self.vault.purge_file("second.txt")
        self.assertEqual(second_purge["deleted_chunks"], 1)
        self.assertEqual(self.vault.status()["chunks"], 0)

    def test_quota_blocks_new_chunks_but_allows_deduplication(self):
        source = self.make_file("quota.bin", b"q" * 1024)
        self.vault.import_file(source, "existing.bin")
        current_usage = self.vault.status()["physical_bytes"]
        self.vault.set_quota(current_usage)
        self.vault.import_file(source, "duplicate.bin")

        other = self.make_file("other.bin", b"different" * 1024)
        with self.assertRaises(QuotaExceeded):
            self.vault.import_file(other, "other.bin")

    def test_corrupt_blob_is_detected(self):
        source = self.make_file("data.bin", b"important data")
        self.vault.import_file(source, "data.bin")
        chunk_id = next((self.vault.control / "blobs").rglob("*"), None)
        while chunk_id is not None and not chunk_id.is_file():
            chunk_id = next((p for p in (self.vault.control / "blobs").rglob("*") if p.is_file()), None)
        self.assertIsNotNone(chunk_id)
        chunk_id.write_bytes(chunk_id.read_bytes()[:-1] + b"x")
        with self.assertRaises(IntegrityError):
            self.vault.verify()

    def test_virtual_path_validation(self):
        self.assertEqual(normalize_virtual_path("photos\\a.jpg"), "photos/a.jpg")
        with self.assertRaises(InvalidVirtualPath):
            normalize_virtual_path("../secret")

    def test_schema_version_one_is_migrated(self):
        import sqlite3

        connection = sqlite3.connect(self.vault.database_path)
        connection.execute("DROP TABLE directories")
        connection.execute("DROP TABLE action_tokens")
        connection.execute("DROP TABLE admin_challenges")
        connection.execute("DROP TABLE access_tokens")
        connection.execute("DROP TABLE auth_challenges")
        connection.execute("DROP TABLE pairing_sessions")
        connection.execute("DROP TABLE devices")
        connection.execute("DROP TABLE upload_session_chunks")
        connection.execute("DROP TABLE upload_sessions")
        connection.execute("DROP TABLE vault_settings")
        connection.execute("UPDATE schema_info SET version = 1")
        connection.commit()
        connection.close()

        migrated = Vault(self.vault.root)
        self.assertIsNone(migrated.get_quota())
        connection = sqlite3.connect(self.vault.database_path)
        version = connection.execute("SELECT version FROM schema_info").fetchone()[0]
        connection.close()
        self.assertEqual(version, 6)

    def test_resumable_upload_out_of_order_and_idempotent_commit(self):
        content = b"abcdefghij"
        session = self.vault.create_upload("uploads/file.bin", len(content), "upload-key-1", chunk_size=4)
        same_session = self.vault.create_upload("uploads/file.bin", len(content), "upload-key-1", chunk_size=4)
        self.assertEqual(session["id"], same_session["id"])

        self.vault.upload_chunk(session["id"], 1, content[4:8])
        with self.assertRaises(UploadConflict):
            self.vault.commit_upload(session["id"])
        self.vault.upload_chunk(session["id"], 0, content[:4])
        self.vault.upload_chunk(session["id"], 2, content[8:])
        duplicate = self.vault.upload_chunk(session["id"], 2, content[8:])
        self.assertTrue(duplicate["deduplicated"])

        status = self.vault.get_upload(session["id"])
        self.assertEqual([item["ordinal"] for item in status["uploaded_chunks"]], [0, 1, 2])
        committed = self.vault.commit_upload(session["id"])
        repeated = self.vault.commit_upload(session["id"])
        self.assertEqual(committed["version_id"], repeated["version_id"])

        destination = self.root / "resumed.bin"
        self.vault.export_file("uploads/file.bin", destination)
        self.assertEqual(destination.read_bytes(), content)

    def test_upload_rejects_conflicting_retry(self):
        session = self.vault.create_upload("conflict.bin", 4, "upload-key-2", chunk_size=4)
        self.vault.upload_chunk(session["id"], 0, b"same")
        with self.assertRaises(UploadConflict):
            self.vault.upload_chunk(session["id"], 0, b"diff")

    def test_terminal_upload_session_can_be_safely_retried(self):
        aborted = self.vault.create_upload("retry.bin", 4, "retry-key", chunk_size=4)
        self.vault.upload_chunk(aborted["id"], 0, b"data")
        self.vault.abort_upload(aborted["id"])
        reopened = self.vault.create_upload("retry.bin", 4, "retry-key", chunk_size=4)
        self.assertEqual(reopened["state"], "open")
        self.assertEqual(reopened["uploaded_chunks"], [])
        self.vault.upload_chunk(reopened["id"], 0, b"data")
        self.vault.commit_upload(reopened["id"])

        self.vault.delete_file("retry.bin")
        after_delete = self.vault.create_upload("retry.bin", 4, "retry-key", chunk_size=4)
        self.assertEqual(after_delete["state"], "open")
        self.vault.commit_upload(after_delete["id"])
        self.assertEqual(self.vault.list_files()[0]["virtual_path"], "retry.bin")

    def test_abort_and_expiry_remove_orphan_blobs(self):
        import sqlite3

        first = self.vault.create_upload("abort.bin", 4, "upload-key-3", chunk_size=4)
        self.vault.upload_chunk(first["id"], 0, b"abcd")
        aborted = self.vault.abort_upload(first["id"])
        self.assertEqual(aborted["deleted_orphan_blobs"], 1)

        second = self.vault.create_upload("expire.bin", 4, "upload-key-4", chunk_size=4)
        self.vault.upload_chunk(second["id"], 0, b"efgh")
        connection = sqlite3.connect(self.vault.database_path)
        connection.execute(
            "UPDATE upload_sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (second["id"],),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(UploadSessionExpired):
            self.vault.commit_upload(second["id"])
        self.assertEqual(self.vault.get_upload(second["id"])["state"], "expired")
        cleaned = self.vault.cleanup_uploads()
        self.assertEqual(cleaned["expired_sessions"], 0)
        self.assertEqual(cleaned["deleted_orphan_blobs"], 1)

    def test_upload_quota_is_enforced_per_new_chunk(self):
        self.vault.set_quota(10)
        session = self.vault.create_upload("too-large.bin", 4, "upload-key-5", chunk_size=4)
        with self.assertRaises(QuotaExceeded):
            self.vault.upload_chunk(session["id"], 0, b"data")

    @staticmethod
    def device_keypair():
        private_key = ed25519.Ed25519PrivateKey.generate()
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return private_key, base64.b64encode(raw).decode("ascii")

    def test_device_pairing_challenge_token_and_revocation(self):
        auth = DeviceAuth(self.vault.database_path)
        private_key, public_key = self.device_keypair()
        pairing = auth.create_pairing()
        device = auth.claim_pairing(pairing["code"], "Test laptop", public_key)
        challenge = auth.create_challenge(device["device_id"])
        signature = private_key.sign(challenge_message(challenge["challenge_id"], challenge["nonce"]))
        token = auth.exchange_token(
            device["device_id"], challenge["challenge_id"], base64.b64encode(signature).decode("ascii")
        )
        verified = auth.verify_token(token["access_token"], "drive:read")
        self.assertEqual(verified["device_id"], device["device_id"])
        with self.assertRaises(AuthenticationError):
            auth.exchange_token(
                device["device_id"], challenge["challenge_id"], base64.b64encode(signature).decode("ascii")
            )
        auth.revoke_device(device["device_id"])
        with self.assertRaises(AuthenticationError):
            auth.verify_token(token["access_token"], "drive:read")

    def test_admin_action_token_is_bound_and_single_use(self):
        from psn_drive.errors import AuthorizationError

        auth = DeviceAuth(self.vault.database_path)
        private_key, public_key = self.device_keypair()
        pairing = auth.create_pairing()
        device = auth.claim_pairing(pairing["code"], "Admin laptop", public_key)
        challenge = auth.create_admin_challenge(device["device_id"], "file.delete", "docs/a.txt")
        signature = private_key.sign(
            admin_challenge_message(
                challenge["challenge_id"], challenge["nonce"], challenge["action"], challenge["resource"]
            )
        )
        token = auth.exchange_admin_token(
            device["device_id"], challenge["challenge_id"], base64.b64encode(signature).decode("ascii")
        )
        with self.assertRaises(AuthorizationError):
            auth.consume_action_token(token["action_token"], device["device_id"], "file.delete", "docs/b.txt")
        auth.consume_action_token(token["action_token"], device["device_id"], "file.delete", "docs/a.txt")
        with self.assertRaises(AuthorizationError):
            auth.consume_action_token(token["action_token"], device["device_id"], "file.delete", "docs/a.txt")

    def test_loopback_http_pairing_auth_upload_and_download(self):
        cert_path = self.vault.control / "tls.crt"
        key_path = self.vault.control / "tls.key"
        fingerprint = create_tls_identity(cert_path, key_path)
        server = DriveHTTPServer(("127.0.0.1", 0), self.vault)
        configure_tls(server, cert_path, key_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"https://127.0.0.1:{server.server_port}"
        insecure_test_context = ssl.create_default_context()
        insecure_test_context.check_hostname = False
        insecure_test_context.verify_mode = ssl.CERT_NONE

        def request_json(path, method="GET", value=None, token=None, extra_headers=None):
            data = json.dumps(value).encode() if value is not None else None
            headers = {"Content-Type": "application/json"} if data else {}
            headers.update(extra_headers or {})
            if token:
                headers["Authorization"] = f"Bearer {token}"
            request = Request(base_url + path, data=data, headers=headers, method=method)
            with urlopen(request, timeout=5, context=insecure_test_context) as response:
                return json.load(response)

        try:
            status, health_body, _ = pinned_request(base_url, fingerprint, "GET", "/v1/health")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(health_body)["status"], "ok")
            with self.assertRaises(CertificatePinError):
                pinned_request(base_url, "0" * 64, "GET", "/v1/health")

            page_request = Request(base_url + "/")
            with urlopen(page_request, timeout=5, context=insecure_test_context) as response:
                page = response.read().decode("utf-8")
                self.assertIn("PSN Drive", page)
                self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")

            with self.assertRaises(HTTPError) as unauthorized:
                request_json("/v1/status")
            self.assertEqual(unauthorized.exception.code, 401)

            private_key, public_key = self.device_keypair()
            pairing = server.auth.create_pairing()
            device = request_json(
                "/v1/pairings/claim",
                "POST",
                {"code": pairing["code"], "device_name": "HTTP device", "public_key": public_key},
            )
            challenge = request_json("/v1/auth/challenges", "POST", {"device_id": device["device_id"]})
            signature = private_key.sign(challenge_message(challenge["challenge_id"], challenge["nonce"]))
            token_response = request_json(
                "/v1/auth/tokens",
                "POST",
                {
                    "device_id": device["device_id"],
                    "challenge_id": challenge["challenge_id"],
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            )
            token = token_response["access_token"]
            session = request_json(
                "/v1/uploads",
                "POST",
                {"virtual_path": "api/file.bin", "expected_size": 4, "chunk_size": 4, "idempotency_key": "http-1"},
                token,
            )
            chunk_request = Request(
                base_url + f"/v1/uploads/{session['id']}/chunks/0",
                data=b"data",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
                method="PUT",
            )
            with urlopen(chunk_request, timeout=5, context=insecure_test_context) as response:
                json.load(response)
            request_json(f"/v1/uploads/{session['id']}/commit", "POST", {}, token)

            download_request = Request(
                base_url + "/v1/download?path=api%2Ffile.bin",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urlopen(download_request, timeout=5, context=insecure_test_context) as response:
                self.assertEqual(response.read(), b"data")
            files = request_json("/v1/files", token=token)
            self.assertEqual(files[0]["virtual_path"], "api/file.bin")

            changed = self.make_file("api-changed.bin", b"next")
            self.vault.import_file(changed, "api/file.bin")
            versions = request_json("/v1/versions?path=api%2Ffile.bin", token=token)
            self.assertEqual(len(versions), 2)
            historical = next(item for item in versions if not item["is_current"])
            restored = request_json(
                "/v1/versions/restore", "POST",
                {"virtual_path":"api/file.bin", "version_id":historical["id"]}, token,
            )
            self.assertTrue(restored["restored"])

            admin_challenge = request_json(
                "/v1/admin/challenges", "POST",
                {"action":"file.delete", "resource":"api/file.bin"}, token,
            )
            admin_signature = private_key.sign(
                admin_challenge_message(
                    admin_challenge["challenge_id"], admin_challenge["nonce"],
                    admin_challenge["action"], admin_challenge["resource"],
                )
            )
            action = request_json(
                "/v1/admin/tokens", "POST",
                {
                    "device_id":device["device_id"],
                    "challenge_id":admin_challenge["challenge_id"],
                    "signature":base64.b64encode(admin_signature).decode("ascii"),
                },
            )
            deleted = request_json(
                "/v1/files/delete", "POST", {"virtual_path":"api/file.bin"}, token,
                {"X-PSN-Action-Token":action["action_token"]},
            )
            self.assertTrue(deleted["deleted"])

            trash = request_json("/v1/trash", token=token)
            self.assertEqual(trash[0]["virtual_path"], "api/file.bin")
            purge_challenge = request_json(
                "/v1/admin/challenges", "POST",
                {"action":"file.purge", "resource":"api/file.bin"}, token,
            )
            purge_signature = private_key.sign(
                admin_challenge_message(
                    purge_challenge["challenge_id"], purge_challenge["nonce"],
                    purge_challenge["action"], purge_challenge["resource"],
                )
            )
            purge_action = request_json(
                "/v1/admin/tokens", "POST",
                {
                    "device_id":device["device_id"],
                    "challenge_id":purge_challenge["challenge_id"],
                    "signature":base64.b64encode(purge_signature).decode("ascii"),
                },
            )
            purged = request_json(
                "/v1/trash/purge", "POST", {"virtual_path":"api/file.bin"}, token,
                {"X-PSN-Action-Token":purge_action["action_token"]},
            )
            self.assertEqual(purged["purged_path"], "api/file.bin")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_tls_identity_and_rate_limiter(self):
        cert_path = self.vault.control / "node.crt"
        key_path = self.vault.control / "node.key"
        fingerprint = create_tls_identity(cert_path, key_path, ["localhost", "127.0.0.1"])
        self.assertEqual(fingerprint, certificate_fingerprint(cert_path))
        self.assertEqual(len(fingerprint), 64)

        limiter = RateLimiter()
        limiter.check(("127.0.0.1", "test"), 2, 60)
        limiter.check(("127.0.0.1", "test"), 2, 60)
        with self.assertRaises(RateLimitExceeded):
            limiter.check(("127.0.0.1", "test"), 2, 60)

    def test_server_config_health_and_windows_service_assets(self):
        config_info = init_server_config(
            self.vault,
            host="127.0.0.1",
            port=7780,
            node_url="https://127.0.0.1:7780",
            service_name="PSNDriveTest",
        )
        config_file = Path(config_info["config_file"])
        self.assertTrue(config_file.is_file())
        config = load_server_config(config_file)
        self.assertEqual(config.service_name, "PSNDriveTest")
        self.assertEqual(len(config.certificate_fingerprint), 64)

        assets = generate_windows_service_assets(config_file, self.root / "service-assets", "python.exe")
        for key in ("runner", "diagnostics", "install_task", "uninstall_task", "winsw_config"):
            self.assertTrue(Path(assets[key]).is_file())
        self.assertIn("server-run --config", Path(assets["runner"]).read_text(encoding="utf-8"))
        self.assertIn("server-diagnostics --config", Path(assets["diagnostics"]).read_text(encoding="utf-8"))
        self.assertIn("Register-ScheduledTask", Path(assets["install_task"]).read_text(encoding="utf-8"))

        cert_path = self.vault.control / "tls.crt"
        key_path = self.vault.control / "tls.key"
        server = DriveHTTPServer(("127.0.0.1", 0), self.vault)
        configure_tls(server, cert_path, key_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            runtime_config = type(config)(
                vault=config.vault,
                host=config.host,
                port=server.server_port,
                allow_lan=config.allow_lan,
                node_url=f"https://127.0.0.1:{server.server_port}",
                certificate_fingerprint=config.certificate_fingerprint,
                service_name=config.service_name,
            )
            health = health_check(runtime_config)
            self.assertTrue(health["healthy"])
            self.assertEqual(health["response"]["service"], "psn-drive")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_service_runtime_lock_logging_status_and_diagnostics(self):
        config_info = init_server_config(self.vault, service_name="PSNDriveDiag")
        config = load_server_config(config_info["config_file"])
        runtime = prepare_service_runtime(self.vault)
        self.assertTrue(Path(runtime["run_directory"]).is_dir())
        self.assertTrue(Path(runtime["logs_directory"]).is_dir())

        with ServiceLock(self.vault):
            from psn_drive.errors import ServiceAlreadyRunning

            with self.assertRaises(ServiceAlreadyRunning):
                with ServiceLock(self.vault):
                    pass
            locked = service_status(self.vault, config)
            self.assertTrue(locked["lock_exists"])
            self.assertEqual(locked["lock"]["version"], "0.16.0")
            self.assertTrue(locked["process_running"])

        with service_logging(self.vault):
            print("diagnostic log line")
        log_path = service_log_path(self.vault)
        self.assertIn("diagnostic log line", log_path.read_text(encoding="utf-8"))
        append_service_event(self.vault, "service.test_event", detail="ok")
        events = list_service_events(self.vault, 10)
        self.assertTrue(any(item["event"] == "service.test_event" for item in events))
        self.assertTrue(service_event_log_path(self.vault).is_file())

        bundle = create_diagnostic_bundle(self.vault, config)
        bundle_path = Path(bundle["path"])
        self.assertTrue(bundle_path.is_file())
        self.assertFalse(bundle["contains_secrets"])
        with zipfile.ZipFile(bundle_path) as archive:
            names = set(archive.namelist())
            self.assertIn("manifest.json", names)
            self.assertIn("service-status.json", names)
            self.assertIn("logs/server-tail.log", names)
            self.assertIn("logs/service-events-tail.jsonl", names)
            self.assertNotIn(".psn/master.key", names)
            self.assertNotIn(".psn/tls.key", names)
            self.assertNotIn(".psn/blobs", names)

    def test_service_preflight_stale_state_cleanup_and_stop(self):
        config_info = init_server_config(self.vault, service_name="PSNDriveLife")
        config = load_server_config(config_info["config_file"])
        preflight = service_preflight(self.vault, config)
        self.assertTrue(preflight["ok"], preflight)

        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((config.host, config.port))
            blocked = service_preflight(self.vault, config)
            port_check = next(item for item in blocked["checks"] if item["name"] == "port_available")
            self.assertFalse(port_check["ok"])

        state_path = service_state_path(self.vault)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({"pid": 99999999, "version": "old"}), encoding="utf-8")
        stale = service_status(self.vault, config)
        self.assertTrue(stale["stale_state"])
        cleaned = cleanup_stale_service_state(self.vault)
        self.assertTrue(cleaned["removed"])
        self.assertFalse(state_path.exists())

        child = subprocess.Popen([
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        ])
        try:
            self.assertTrue(process_is_running(child.pid))
            state_path.write_text(json.dumps({"pid": child.pid, "version": "test"}), encoding="utf-8")
            stopped = stop_service(self.vault, timeout_seconds=5)
            self.assertTrue(stopped["stopped"], stopped)
            self.assertFalse(process_is_running(child.pid))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)

    def test_windows_folder_sync_end_to_end(self):
        cert_path = self.vault.control / "tls.crt"
        key_path = self.vault.control / "tls.key"
        fingerprint = create_tls_identity(cert_path, key_path)
        server = DriveHTTPServer(("127.0.0.1", 0), self.vault)
        configure_tls(server, cert_path, key_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"https://127.0.0.1:{server.server_port}"

        private_key, public_key = self.device_keypair()
        pairing = server.auth.create_pairing()
        device = server.auth.claim_pairing(pairing["code"], "Sync laptop", public_key)
        device_key_path = self.root / "sync-device.key"
        device_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        sync_root = self.root / "sync-root"
        (sync_root / "documents").mkdir(parents=True)
        (sync_root / "hello.txt").write_text("hello", encoding="utf-8")
        (sync_root / "documents" / "note.txt").write_text("note", encoding="utf-8")
        config = SyncConfig(
            node_url=base_url,
            certificate_fingerprint=fingerprint,
            device_id=device["device_id"],
            key_file=str(device_key_path),
            local_root=str(sync_root),
            remote_prefix="computers/test-laptop",
        )
        client = SyncClient(config)
        try:
            first = client.run()
            self.assertEqual(first["uploaded"], 2)
            self.assertEqual(first["failed"], 0)
            second = client.run()
            self.assertEqual(second["unchanged"], 2)

            (sync_root / "hello.txt").write_text("hello version two", encoding="utf-8")
            third = client.run()
            self.assertEqual(third["uploaded"], 1)
            (sync_root / "documents" / "note.txt").unlink()
            fourth = client.run()
            self.assertEqual(fourth["missing"], 1)
            status = client.status()
            self.assertEqual(status["synced_files"], 1)
            self.assertEqual(status["missing_local_files"], 1)

            remote_paths = {item["virtual_path"] for item in self.vault.list_files()}
            self.assertIn("computers/test-laptop/hello.txt", remote_paths)
            self.assertIn("computers/test-laptop/documents/note.txt", remote_paths)
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_windows_sync_background_scripts_are_generated(self):
        sync_root = self.root / "sync-script-root"
        sync_root.mkdir()
        device_key = self.root / "sync-script-device.key"
        device_key.write_text("placeholder", encoding="utf-8")
        config = SyncConfig(
            node_url="https://127.0.0.1:7780",
            certificate_fingerprint="0" * 64,
            device_id="device-for-scripts",
            key_file=str(device_key),
            local_root=str(sync_root),
            remote_prefix="computers/scripts",
        )
        config_file = self.root / "sync-script.json"
        config.save(config_file)
        assets = generate_windows_sync_assets(
            config_file,
            self.root / "sync-assets",
            "python.exe",
            interval_seconds=120,
            task_name="PSNDriveSyncTest",
        )
        for key in ("run_once", "watch", "status", "install_startup", "install_periodic", "uninstall"):
            self.assertTrue(Path(assets[key]).is_file(), key)
        self.assertIn("sync-watch", Path(assets["watch"]).read_text(encoding="utf-8"))
        self.assertIn("--interval 120", Path(assets["watch"]).read_text(encoding="utf-8"))
        self.assertIn("Register-ScheduledTask", Path(assets["install_startup"]).read_text(encoding="utf-8"))
        self.assertIn("MultipleInstances IgnoreNew", Path(assets["install_startup"]).read_text(encoding="utf-8"))
        self.assertIn("sync-status", Path(assets["status"]).read_text(encoding="utf-8"))
        self.assertIn("Unregister-ScheduledTask", Path(assets["uninstall"]).read_text(encoding="utf-8"))

    def test_sync_lock_rejects_parallel_instance(self):
        lock_path = self.root / "sync-lock" / "sync.lock"
        with SyncLock(lock_path):
            with self.assertRaises(SyncAlreadyRunning):
                with SyncLock(lock_path):
                    pass
        with SyncLock(lock_path):
            pass


if __name__ == "__main__":
    unittest.main()
