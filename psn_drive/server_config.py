import json
import os
import sys
from dataclasses import dataclass
from xml.sax.saxutils import escape
from pathlib import Path
from urllib.parse import urlsplit

from .device_client import pinned_request
from .tls import certificate_fingerprint, create_tls_identity


CONFIG_VERSION = 1
DEFAULT_CONFIG_NAME = "server.json"


@dataclass(frozen=True)
class ServerConfig:
    vault: str
    host: str = "127.0.0.1"
    port: int = 7780
    allow_lan: bool = False
    node_url: str | None = None
    certificate_fingerprint: str | None = None
    service_name: str = "PSNDrive"

    @property
    def effective_url(self) -> str:
        if self.node_url:
            return self.node_url.rstrip("/")
        host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        return f"https://{host}:{self.port}"

    def validate(self) -> None:
        if not self.vault:
            raise ValueError("server config vault is required")
        if not (1 <= int(self.port) <= 65535):
            raise ValueError("server config port must be between 1 and 65535")
        if self.host not in ("127.0.0.1", "localhost", "::1") and not self.allow_lan:
            raise ValueError("non-loopback server config requires allow_lan=true")
        parsed = urlsplit(self.effective_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("server config node_url must be an https URL")

    def to_dict(self) -> dict:
        return {
            "version": CONFIG_VERSION,
            "vault": self.vault,
            "host": self.host,
            "port": self.port,
            "allow_lan": self.allow_lan,
            "node_url": self.effective_url,
            "certificate_fingerprint": self.certificate_fingerprint,
            "service_name": self.service_name,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "ServerConfig":
        if value.get("version") != CONFIG_VERSION:
            raise ValueError("unsupported server config version")
        config = cls(
            vault=str(value["vault"]),
            host=str(value.get("host", "127.0.0.1")),
            port=int(value.get("port", 7780)),
            allow_lan=bool(value.get("allow_lan", False)),
            node_url=value.get("node_url"),
            certificate_fingerprint=value.get("certificate_fingerprint"),
            service_name=str(value.get("service_name", "PSNDrive")),
        )
        config.validate()
        return config


def default_config_path(vault) -> Path:
    return vault.control / DEFAULT_CONFIG_NAME


def save_server_config(config: ServerConfig, path: Path | str) -> dict:
    config.validate()
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(config.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return {**config.to_dict(), "config_file": str(target)}


def load_server_config(path: Path | str) -> ServerConfig:
    return ServerConfig.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def init_server_config(
    vault,
    host: str = "127.0.0.1",
    port: int = 7780,
    allow_lan: bool = False,
    node_url: str | None = None,
    service_name: str = "PSNDrive",
    san: list[str] | None = None,
    force_tls: bool = False,
) -> dict:
    cert_path = vault.control / "tls.crt"
    key_path = vault.control / "tls.key"
    if not cert_path.exists() or not key_path.exists():
        hosts = ["localhost", "127.0.0.1", host, *(san or [])]
        fingerprint = create_tls_identity(cert_path, key_path, hosts)
        tls_created = True
    elif force_tls:
        raise FileExistsError("TLS identity already exists; refusing to overwrite")
    else:
        fingerprint = certificate_fingerprint(cert_path)
        tls_created = False
    config = ServerConfig(
        vault=str(vault.root),
        host=host,
        port=port,
        allow_lan=allow_lan,
        node_url=node_url or f"https://{host}:{port}",
        certificate_fingerprint=fingerprint,
        service_name=service_name,
    )
    saved = save_server_config(config, default_config_path(vault))
    saved["tls_created"] = tls_created
    return saved


def show_server_config(vault, config_file: Path | str | None = None) -> dict:
    path = Path(config_file).expanduser().resolve() if config_file else default_config_path(vault)
    config = load_server_config(path)
    result = config.to_dict()
    result["config_file"] = str(path)
    result["tls_certificate"] = str(vault.control / "tls.crt")
    return result


def health_check(config: ServerConfig) -> dict:
    if not config.certificate_fingerprint:
        raise ValueError("server config is missing certificate_fingerprint")
    status, body, _ = pinned_request(config.effective_url, config.certificate_fingerprint, "GET", "/v1/health")
    return {
        "healthy": status == 200,
        "status": status,
        "node_url": config.effective_url,
        "response": json.loads(body),
    }


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def generate_windows_service_assets(
    config_file: Path | str,
    output_dir: Path | str,
    python_executable: str | None = None,
) -> dict:
    config_path = Path(config_file).expanduser().resolve()
    config = load_server_config(config_path)
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    python_path = python_executable or sys.executable
    service_name = config.service_name

    runner = output / "psn-drive-service-run.ps1"
    install_task = output / "install-startup-task.ps1"
    uninstall_task = output / "uninstall-startup-task.ps1"
    winsw = output / "winsw-service.xml"

    runner.write_text(
        "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$Python = {powershell_quote(python_path)}",
                f"$Config = {powershell_quote(str(config_path))}",
                "& $Python -m psn_drive.cli server-run --config $Config",
                "",
            ]
        ),
        encoding="utf-8",
    )
    install_task.write_text(
        "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$TaskName = {powershell_quote(service_name)}",
                f"$Script = {powershell_quote(str(runner))}",
                "$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -ExecutionPolicy Bypass -File `\"$Script`\"\"",
                "$Trigger = New-ScheduledTaskTrigger -AtStartup",
                "$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DisallowStartIfOnBatteries:$false -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)",
                "Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description 'PSN Drive server prototype' -RunLevel Highest -Force",
                "Start-ScheduledTask -TaskName $TaskName",
                "Write-Host \"Installed and started scheduled task $TaskName\"",
                "",
            ]
        ),
        encoding="utf-8",
    )
    uninstall_task.write_text(
        "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$TaskName = {powershell_quote(service_name)}",
                "Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue",
                "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false",
                "Write-Host \"Uninstalled scheduled task $TaskName\"",
                "",
            ]
        ),
        encoding="utf-8",
    )
    winsw.write_text(
        "\n".join(
            [
                "<service>",
                f"  <id>{escape(service_name)}</id>",
                "  <name>PSN Drive Server</name>",
                "  <description>PSN Drive server prototype. Requires WinSW.exe next to this XML.</description>",
                f"  <executable>{escape(python_path)}</executable>",
                f"  <arguments>-m psn_drive.cli server-run --config &quot;{escape(str(config_path))}&quot;</arguments>",
                "  <log mode=\"roll-by-size-time\" />",
                "  <onfailure action=\"restart\" delay=\"10 sec\" />",
                "</service>",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "service_name": service_name,
        "output_dir": str(output),
        "runner": str(runner),
        "install_task": str(install_task),
        "uninstall_task": str(uninstall_task),
        "winsw_config": str(winsw),
        "config_file": str(config_path),
    }
