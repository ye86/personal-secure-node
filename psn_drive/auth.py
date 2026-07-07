import base64
import hashlib
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .database import connect
from .errors import AuthenticationError, AuthorizationError, PairingError


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def challenge_message(challenge_id: str, nonce: str) -> bytes:
    return f"psn-drive-auth-v1\n{challenge_id}\n{nonce}".encode("ascii")


def admin_challenge_message(
    challenge_id: str, nonce: str, action: str, resource: str
) -> bytes:
    return f"psn-drive-admin-v1\n{challenge_id}\n{nonce}\n{action}\n{resource}".encode("utf-8")


class DeviceAuth:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        return connect(self.database_path)

    def create_pairing(self, ttl_seconds: int = 300) -> dict:
        if ttl_seconds < 30 or ttl_seconds > 3600:
            raise ValueError("pairing TTL must be between 30 and 3600 seconds")
        code = secrets.token_urlsafe(24)
        created = now_utc()
        pairing_id = uuid.uuid4().hex
        expires = created + timedelta(seconds=ttl_seconds)
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO pairing_sessions(id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (pairing_id, token_hash(code), created.isoformat(), expires.isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        return {"pairing_id": pairing_id, "code": code, "expires_at": expires.isoformat()}

    def claim_pairing(self, code: str, device_name: str, public_key_b64: str) -> dict:
        device_name = device_name.strip()
        if not device_name or len(device_name) > 100:
            raise PairingError("device name must contain 1 to 100 characters")
        try:
            public_bytes = base64.b64decode(public_key_b64, validate=True)
            ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        except Exception as exc:
            raise PairingError("invalid Ed25519 public key") from exc

        now = now_utc()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            pairing = conn.execute(
                "SELECT * FROM pairing_sessions WHERE code_hash = ?", (token_hash(code),)
            ).fetchone()
            if pairing is None or pairing["used_at"] is not None:
                raise PairingError("pairing code is invalid or already used")
            if datetime.fromisoformat(pairing["expires_at"]) <= now:
                raise PairingError("pairing code has expired")
            existing = conn.execute(
                "SELECT id, name, status FROM devices WHERE public_key = ?", (public_key_b64,)
            ).fetchone()
            if existing is not None:
                raise PairingError("device key is already registered")
            device_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO devices(id, name, public_key, status, created_at) VALUES (?, ?, ?, 'active', ?)",
                (device_id, device_name, public_key_b64, now.isoformat()),
            )
            conn.execute("UPDATE pairing_sessions SET used_at = ? WHERE id = ?", (now.isoformat(), pairing["id"]))
            conn.commit()
            return {"device_id": device_id, "name": device_name, "status": "active"}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_challenge(self, device_id: str, ttl_seconds: int = 120) -> dict:
        if ttl_seconds < 10 or ttl_seconds > 300:
            raise ValueError("challenge TTL must be between 10 and 300 seconds")
        created = now_utc()
        expires = created + timedelta(seconds=ttl_seconds)
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        challenge_id = uuid.uuid4().hex
        conn = self._connect()
        try:
            device = conn.execute("SELECT status FROM devices WHERE id = ?", (device_id,)).fetchone()
            if device is None or device["status"] != "active":
                raise AuthenticationError("unknown or revoked device")
            conn.execute(
                """
                INSERT INTO auth_challenges(id, device_id, nonce, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (challenge_id, device_id, nonce, created.isoformat(), expires.isoformat()),
            )
            conn.commit()
            return {"challenge_id": challenge_id, "nonce": nonce, "expires_at": expires.isoformat()}
        finally:
            conn.close()

    def exchange_token(
        self,
        device_id: str,
        challenge_id: str,
        signature_b64: str,
        ttl_seconds: int = 900,
        scopes: tuple[str, ...] = ("drive:read", "drive:write"),
    ) -> dict:
        if ttl_seconds < 60 or ttl_seconds > 3600:
            raise ValueError("token TTL must be between 60 and 3600 seconds")
        now = now_utc()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            device = conn.execute(
                "SELECT public_key, status FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
            challenge = conn.execute(
                "SELECT * FROM auth_challenges WHERE id = ? AND device_id = ?",
                (challenge_id, device_id),
            ).fetchone()
            if device is None or device["status"] != "active" or challenge is None:
                raise AuthenticationError("invalid device or challenge")
            if challenge["used_at"] is not None:
                raise AuthenticationError("challenge was already used")
            if datetime.fromisoformat(challenge["expires_at"]) <= now:
                raise AuthenticationError("challenge has expired")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(device["public_key"]))
                public_key.verify(signature, challenge_message(challenge_id, challenge["nonce"]))
            except (ValueError, InvalidSignature) as exc:
                raise AuthenticationError("invalid challenge signature") from exc

            raw_token = secrets.token_urlsafe(32)
            token_id = uuid.uuid4().hex
            expires = now + timedelta(seconds=ttl_seconds)
            scope_text = " ".join(sorted(set(scopes)))
            conn.execute("UPDATE auth_challenges SET used_at = ? WHERE id = ?", (now.isoformat(), challenge_id))
            conn.execute(
                """
                INSERT INTO access_tokens(id, device_id, token_hash, scopes, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_id, device_id, token_hash(raw_token), scope_text, now.isoformat(), expires.isoformat()),
            )
            conn.commit()
            return {"access_token": raw_token, "token_type": "Bearer", "expires_at": expires.isoformat(), "scopes": scope_text.split()}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def verify_token(self, raw_token: str, required_scope: str) -> dict:
        now = now_utc()
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT t.id AS token_id, t.device_id, t.scopes, t.expires_at,
                       t.revoked_at, d.name, d.status
                FROM access_tokens t JOIN devices d ON d.id = t.device_id
                WHERE t.token_hash = ?
                """,
                (token_hash(raw_token),),
            ).fetchone()
            if row is None or row["revoked_at"] is not None or row["status"] != "active":
                raise AuthenticationError("invalid or revoked access token")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise AuthenticationError("access token has expired")
            scopes = set(row["scopes"].split())
            if required_scope not in scopes:
                raise AuthorizationError(f"token lacks scope: {required_scope}")
            conn.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now.isoformat(), row["device_id"]))
            conn.commit()
            return {"device_id": row["device_id"], "device_name": row["name"], "scopes": sorted(scopes)}
        finally:
            conn.close()

    def list_devices(self) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, name, status, created_at, last_seen_at, revoked_at FROM devices ORDER BY created_at"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def revoke_device(self, device_id: str) -> None:
        now = now_utc().isoformat()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE devices SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'",
                (now, device_id),
            )
            if cursor.rowcount != 1:
                raise AuthenticationError("unknown or already revoked device")
            conn.execute(
                "UPDATE access_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
                (now, device_id),
            )
            conn.execute(
                "UPDATE action_tokens SET used_at = ? WHERE device_id = ? AND used_at IS NULL",
                (now, device_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_admin_challenge(
        self, device_id: str, action: str, resource: str, ttl_seconds: int = 120
    ) -> dict:
        if action not in ("file.delete", "file.purge"):
            raise AuthorizationError("unsupported administrator action")
        if not resource or len(resource) > 1024:
            raise ValueError("administrator resource is invalid")
        created = now_utc()
        expires = created + timedelta(seconds=ttl_seconds)
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        challenge_id = uuid.uuid4().hex
        conn = self._connect()
        try:
            device = conn.execute("SELECT status FROM devices WHERE id = ?", (device_id,)).fetchone()
            if device is None or device["status"] != "active":
                raise AuthenticationError("unknown or revoked device")
            conn.execute(
                """
                INSERT INTO admin_challenges(
                    id, device_id, action, resource, nonce, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id, device_id, action, resource, nonce,
                    created.isoformat(), expires.isoformat(),
                ),
            )
            conn.commit()
            return {
                "challenge_id": challenge_id,
                "nonce": nonce,
                "action": action,
                "resource": resource,
                "expires_at": expires.isoformat(),
            }
        finally:
            conn.close()

    def exchange_admin_token(
        self, device_id: str, challenge_id: str, signature_b64: str, ttl_seconds: int = 300
    ) -> dict:
        now = now_utc()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            device = conn.execute(
                "SELECT public_key, status FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
            challenge = conn.execute(
                "SELECT * FROM admin_challenges WHERE id = ? AND device_id = ?",
                (challenge_id, device_id),
            ).fetchone()
            if device is None or device["status"] != "active" or challenge is None:
                raise AuthenticationError("invalid administrator challenge")
            if challenge["used_at"] is not None or datetime.fromisoformat(challenge["expires_at"]) <= now:
                raise AuthenticationError("administrator challenge is expired or already used")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(device["public_key"]))
                public_key.verify(
                    signature,
                    admin_challenge_message(
                        challenge_id,
                        challenge["nonce"],
                        challenge["action"],
                        challenge["resource"],
                    ),
                )
            except (ValueError, InvalidSignature) as exc:
                raise AuthenticationError("invalid administrator signature") from exc
            raw_token = secrets.token_urlsafe(32)
            expires = now + timedelta(seconds=ttl_seconds)
            conn.execute("UPDATE admin_challenges SET used_at = ? WHERE id = ?", (now.isoformat(), challenge_id))
            conn.execute(
                """
                INSERT INTO action_tokens(
                    id, device_id, action, resource, token_hash, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex, device_id, challenge["action"], challenge["resource"],
                    token_hash(raw_token), now.isoformat(), expires.isoformat(),
                ),
            )
            conn.commit()
            return {
                "action_token": raw_token,
                "action": challenge["action"],
                "resource": challenge["resource"],
                "expires_at": expires.isoformat(),
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def consume_action_token(
        self, raw_token: str, device_id: str, action: str, resource: str
    ) -> None:
        now = now_utc()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT t.* FROM action_tokens t JOIN devices d ON d.id = t.device_id
                WHERE t.token_hash = ? AND t.device_id = ? AND t.action = ? AND t.resource = ?
                  AND d.status = 'active'
                """,
                (token_hash(raw_token), device_id, action, resource),
            ).fetchone()
            if row is None or row["used_at"] is not None:
                raise AuthorizationError("administrator action token is invalid or already used")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise AuthorizationError("administrator action token has expired")
            conn.execute("UPDATE action_tokens SET used_at = ? WHERE id = ?", (now.isoformat(), row["id"]))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
