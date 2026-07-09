import os
import shutil
import stat
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


SOURCE_FILES = [
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "cli.py",
    "drive.py",
    "export_pubkey.py",
    "psn-core.md",
    "psn-protocol.md",
    "pyproject.toml",
    "requirements.txt",
]

SOURCE_DIRECTORIES = ["docs", "origin", "psn", "psn_drive"]

EXCLUDED_NAMES = {
    ".git",
    ".agents",
    ".codex",
    ".tmp",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "test-tmp",
    "tmp-test-permission",
}

EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".log"}
SECRET_NAMES = {"identity.key", "public.key"}


def _ignore(_directory, names):
    ignored = set()
    for name in names:
        if name in EXCLUDED_NAMES or name in SECRET_NAMES:
            ignored.add(name)
        if name.startswith("sqlite-probe-"):
            ignored.add(name)
        if Path(name).suffix in EXCLUDED_SUFFIXES:
            ignored.add(name)
    return ignored


def _copy_source(project_root: Path, source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for name in SOURCE_FILES:
        source = project_root / name
        if source.is_file():
            shutil.copy2(source, source_dir / name)
    for name in SOURCE_DIRECTORIES:
        source = project_root / name
        if source.is_dir():
            shutil.copytree(source, source_dir / name, ignore=_ignore)


def _write(path: Path, text: str, executable: bool = False) -> None:
    path.write_text(text.replace("\n", os.linesep if path.suffix.lower() in {".ps1", ".cmd"} else "\n"), encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _windows_installer() -> str:
    return r'''param(
  [string]$InstallDir = "$env:ProgramData\PSNDrive",
  [string]$Vault = "$env:ProgramData\PSNDrive\vault",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 7780,
  [string]$ServiceName = "PSNDrive",
  [switch]$AllowLan
)

$ErrorActionPreference = "Stop"
$Source = Join-Path $PSScriptRoot "source"
$Venv = Join-Path $InstallDir ".venv"
$Python = Join-Path $Venv "Scripts\python.exe"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $Vault | Out-Null

if (!(Test-Path $Python)) {
  py -3 -m venv $Venv
}

& $Python -m pip install --upgrade pip
& $Python -m pip install $Source

if (!(Test-Path (Join-Path $Vault ".psn"))) {
  & $Python -m psn_drive.cli --vault $Vault init
}

$Args = @("--vault", $Vault, "server-config-init", "--host", $HostName, "--port", "$Port", "--service-name", $ServiceName)
if ($AllowLan) { $Args += "--allow-lan" }
& $Python -m psn_drive.cli @Args
& $Python -m psn_drive.cli --vault $Vault windows-service-scripts --python $Python

$InstallTask = Join-Path $Vault ".psn\service\windows\install-startup-task.ps1"
PowerShell -NoProfile -ExecutionPolicy Bypass -File $InstallTask

Write-Host ""
Write-Host "PSN Drive installed."
Write-Host "Vault: $Vault"
Write-Host "URL: https://$HostName`:$Port/"
Write-Host "Open the Web UI and use device-login to connect a browser/device."
'''


def _windows_uninstaller() -> str:
    return r'''param(
  [string]$Vault = "$env:ProgramData\PSNDrive\vault"
)

$ErrorActionPreference = "Stop"
$UninstallTask = Join-Path $Vault ".psn\service\windows\uninstall-startup-task.ps1"
if (Test-Path $UninstallTask) {
  PowerShell -NoProfile -ExecutionPolicy Bypass -File $UninstallTask
} else {
  Write-Host "No scheduled task uninstall script found at $UninstallTask"
}
Write-Host "Vault data is preserved at $Vault"
'''


def _linux_installer() -> str:
    return r'''#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/psn-drive}"
VAULT="${VAULT:-$HOME/PSNDriveVault}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-7780}"
SERVICE_NAME="${SERVICE_NAME:-psn-drive}"
ALLOW_LAN="${ALLOW_LAN:-0}"

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/source"
VENV="$INSTALL_DIR/.venv"
PYTHON="$VENV/bin/python"

mkdir -p "$INSTALL_DIR" "$VAULT"

if [ ! -x "$PYTHON" ]; then
  python3 -m venv "$VENV"
fi

"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install "$SOURCE"

if [ ! -d "$VAULT/.psn" ]; then
  "$PYTHON" -m psn_drive.cli --vault "$VAULT" init
fi

CONFIG_ARGS=(--vault "$VAULT" server-config-init --host "$HOST" --port "$PORT" --service-name "$SERVICE_NAME")
if [ "$ALLOW_LAN" = "1" ]; then
  CONFIG_ARGS+=(--allow-lan)
fi
"$PYTHON" -m psn_drive.cli "${CONFIG_ARGS[@]}"

SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
SERVICE_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=PSN Drive personal data node
After=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON -m psn_drive.cli server-run --config $VAULT/.psn/server.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload
  systemctl --user enable --now "$SERVICE_NAME.service" || {
    echo "systemd user service could not be started automatically."
    echo "Manual start command:"
    echo "$PYTHON -m psn_drive.cli server-run --config $VAULT/.psn/server.json"
    exit 0
  }
else
  echo "systemctl not found. Manual start command:"
  echo "$PYTHON -m psn_drive.cli server-run --config $VAULT/.psn/server.json"
fi

echo ""
echo "PSN Drive installed."
echo "Vault: $VAULT"
echo "URL: https://$HOST:$PORT/"
echo "Open the Web UI and use device-login to connect a browser/device."
'''


def _linux_uninstaller() -> str:
    return r'''#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-psn-drive}"
VAULT="${VAULT:-$HOME/PSNDriveVault}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now "$SERVICE_NAME.service" || true
  rm -f "$HOME/.config/systemd/user/$SERVICE_NAME.service"
  systemctl --user daemon-reload || true
fi

echo "PSN Drive service uninstalled. Vault data is preserved at $VAULT"
'''


def _release_readme(version: str) -> str:
    return f"""# PSN Drive {version} release package

This package contains PSN Drive source plus practical Windows and Linux install scripts.

## Windows

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\\install-windows.ps1
```

Optional LAN binding:

```powershell
.\\install-windows.ps1 -HostName 0.0.0.0 -AllowLan
```

Uninstall scheduled task only, preserving data:

```powershell
.\\uninstall-windows.ps1
```

## Linux

```bash
chmod +x install-linux.sh uninstall-linux.sh
./install-linux.sh
```

Optional LAN binding:

```bash
HOST=0.0.0.0 ALLOW_LAN=1 ./install-linux.sh
```

Uninstall systemd user service only, preserving data:

```bash
./uninstall-linux.sh
```

## Notes

- The installer creates a Python virtual environment and installs the bundled source.
- Python 3.10+ is required.
- pip still needs access to Python dependencies unless they are already cached.
- This is not yet MSI/deb/rpm; it is a v1.0-oriented practical deployment bundle.
- Do not expose the node directly to the public internet yet.
"""


def _zip_directory(source: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source.parent).as_posix())


def generate_release_package(project_root: Path | str, output_dir: Path | str, version: str | None = None) -> dict:
    project_root = Path(project_root).resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    version = version or __version__
    package_name = f"psn-drive-{version}"
    staging = output_dir / package_name
    archive_path = output_dir / f"{package_name}.zip"
    if staging.exists():
        shutil.rmtree(staging)
    if archive_path.exists():
        archive_path.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)
    staging.mkdir()

    _copy_source(project_root, staging / "source")
    _write(staging / "install-windows.ps1", _windows_installer())
    _write(staging / "uninstall-windows.ps1", _windows_uninstaller())
    _write(staging / "install-linux.sh", _linux_installer(), executable=True)
    _write(staging / "uninstall-linux.sh", _linux_uninstaller(), executable=True)
    _write(staging / "RELEASE_README.md", _release_readme(version))
    _write(
        staging / "release-manifest.json",
        "{\n"
        f"  \"name\": \"psn-drive\",\n"
        f"  \"version\": \"{version}\",\n"
        f"  \"created_at\": \"{datetime.now(timezone.utc).isoformat()}\",\n"
        f"  \"python\": \"{sys.version.split()[0]}\"\n"
        "}\n",
    )
    _zip_directory(staging, archive_path)
    return {
        "name": package_name,
        "version": version,
        "directory": str(staging),
        "archive": str(archive_path),
        "bytes": archive_path.stat().st_size,
        "windows_installer": str(staging / "install-windows.ps1"),
        "linux_installer": str(staging / "install-linux.sh"),
    }
