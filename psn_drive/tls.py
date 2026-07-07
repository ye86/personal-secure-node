import hashlib
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def create_tls_identity(cert_path: Path, key_path: Path, hosts: list[str] | None = None) -> str:
    if cert_path.exists() or key_path.exists():
        raise FileExistsError("TLS certificate or key already exists")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    hosts = hosts or ["localhost", "127.0.0.1"]
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PSN Drive Node")])
    san_values = []
    for host in hosts:
        try:
            san_values.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_values.append(x509.DNSName(host))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
    except OSError:
        pass
    return certificate_fingerprint(cert_path)


def certificate_fingerprint(cert_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = certificate.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def normalize_fingerprint(value: str) -> str:
    normalized = value.lower().strip()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    normalized = normalized.replace(":", "")
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("invalid SHA-256 certificate fingerprint")
    return normalized
