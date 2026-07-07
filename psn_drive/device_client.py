import base64
import hashlib
import http.client
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from .auth import admin_challenge_message, challenge_message
from .device_keys import load_device_key, public_key_b64
from .errors import CertificatePinError, HTTPClientError
from .tls import normalize_fingerprint


def pinned_raw_request(
    base_url: str,
    fingerprint: str,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict | None = None,
) -> tuple[int, bytes, dict]:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("PSN Drive v0.5 requires an https URL without embedded credentials")
    expected_fingerprint = normalize_fingerprint(fingerprint)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=10)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
        actual_fingerprint = hashlib.sha256(certificate).hexdigest()
        if not secrets_compare(actual_fingerprint, expected_fingerprint):
            raise CertificatePinError(
                f"server certificate fingerprint mismatch: expected {expected_fingerprint}, got {actual_fingerprint}"
            )
        prefix = parsed.path.rstrip("/")
        request_path = prefix + path
        connection.request(method, request_path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_body = response.read()
        headers_out = dict(response.getheaders())
        if response.status >= 400:
            try:
                error = json.loads(response_body)
                message = error.get("message", f"HTTP {response.status}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                message = f"HTTP {response.status}"
            raise HTTPClientError(response.status, message)
        return response.status, response_body, headers_out
    finally:
        connection.close()


def pinned_request(
    base_url: str,
    fingerprint: str,
    method: str,
    path: str,
    value: dict | None = None,
    token: str | None = None,
) -> tuple[int, bytes, dict]:
    body = json.dumps(value).encode("utf-8") if value is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return pinned_raw_request(base_url, fingerprint, method, path, body, headers)


def secrets_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def post_json(base_url: str, fingerprint: str, path: str, value: dict) -> dict:
    _, body, _ = pinned_request(base_url, fingerprint, "POST", path, value)
    return json.loads(body)


def claim_device(base_url: str, fingerprint: str, code: str, name: str, key_path: Path) -> dict:
    private_key = load_device_key(key_path)
    return post_json(
        base_url,
        fingerprint,
        "/v1/pairings/claim",
        {"code": code, "device_name": name, "public_key": public_key_b64(private_key)},
    )


def login_device(base_url: str, fingerprint: str, device_id: str, key_path: Path) -> dict:
    private_key = load_device_key(key_path)
    challenge = post_json(base_url, fingerprint, "/v1/auth/challenges", {"device_id": device_id})
    signature = private_key.sign(challenge_message(challenge["challenge_id"], challenge["nonce"]))
    return post_json(
        base_url,
        fingerprint,
        "/v1/auth/tokens",
        {
            "device_id": device_id,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    )


def authorize_admin_action(
    base_url: str,
    fingerprint: str,
    device_id: str,
    key_path: Path,
    action: str,
    resource: str,
) -> dict:
    private_key = load_device_key(key_path)
    login = login_device(base_url, fingerprint, device_id, key_path)
    _, challenge_body, _ = pinned_request(
        base_url,
        fingerprint,
        "POST",
        "/v1/admin/challenges",
        {"action": action, "resource": resource},
        login["access_token"],
    )
    challenge = json.loads(challenge_body)
    signature = private_key.sign(
        admin_challenge_message(
            challenge["challenge_id"], challenge["nonce"], challenge["action"], challenge["resource"]
        )
    )
    return post_json(
        base_url,
        fingerprint,
        "/v1/admin/tokens",
        {
            "device_id": device_id,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    )
