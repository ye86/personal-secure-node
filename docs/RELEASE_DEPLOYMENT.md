# Windows与Linux发布包部署（v0.21）

v0.21新增发布包生成器，用于生成一个可分发的 `.zip` 包。它面向早期DIY用户，目标是“下载、解压、一键安装、能后台运行”。

它还不是正式MSI、deb或rpm，也没有做离线依赖仓库。安装脚本会创建Python虚拟环境，并从发布包内的源码安装PSN Drive。

## 生成发布包

在项目根目录运行：

```powershell
python drive.py release-package --output dist
```

解压后包含：

```text
psn-drive-0.21.0/
├── source/
├── install-windows.ps1
├── uninstall-windows.ps1
├── install-linux.sh
├── uninstall-linux.sh
├── RELEASE_README.md
└── release-manifest.json
```

发布包会排除 `.git`、本地密钥、Vault数据、临时目录、缓存和pyc文件。

## Windows安装

以管理员身份打开PowerShell，在解压目录运行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
```

默认安装到 `%ProgramData%\PSNDrive`，Vault位于 `%ProgramData%\PSNDrive\vault`，通过Windows任务计划后台运行。

局域网监听示例：

```powershell
.\install-windows.ps1 -HostName 0.0.0.0 -AllowLan
```

卸载后台任务但保留数据：

```powershell
.\uninstall-windows.ps1
```

## Linux安装

在解压目录运行：

```bash
chmod +x install-linux.sh uninstall-linux.sh
./install-linux.sh
```

默认安装到 `~/.local/share/psn-drive`，Vault位于 `~/PSNDriveVault`，通过systemd用户服务后台运行。

局域网监听示例：

```bash
HOST=0.0.0.0 ALLOW_LAN=1 ./install-linux.sh
```

卸载systemd用户服务但保留数据：

```bash
./uninstall-linux.sh
```

## 当前限制

- 依赖安装仍依赖pip访问依赖源或本机缓存；
- Windows使用任务计划，还不是签名MSI和正式Windows服务；
- Linux使用systemd用户服务，暂不生成deb/rpm；
- 没有自动升级通道；
- 没有公网反向代理或域名配置向导；
- 不建议直接暴露公网。
