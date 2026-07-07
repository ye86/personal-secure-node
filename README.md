# PSN Node

> 面向个人数据主权的个人互联网节点（早期研究原型）

PSN Node 设想让个人拥有自己的长期数字身份、数据空间和网络节点。节点可以运行在家庭服务器或用户选择的云端，通过域名完成发现，并在用户授权下与其他节点和应用交换数据。

本项目不是一个已经可投入生产的操作系统，也不是传统 NAS、聊天软件或云盘的简单替代品。当前仓库仅用于验证身份密钥、节点发现、会话密钥和加密消息等基础概念。

## 项目原则

- **用户拥有数据**：应用只有有限、可撤销的使用权。
- **身份独立于平台**：域名用于发现，密码学身份用于验证。
- **默认拒绝**：数据读取、修改、存储和外发分别授权。
- **本地优先**：家庭节点优先，云端和中继是可替换组件。
- **最小暴露**：节点、应用和设备只获得完成任务所需的能力。
- **可迁移、可恢复**：更换应用、设备或服务器不应丢失身份与数据。
- **兼容式演进**：先与 Windows 和现有互联网服务协作，再逐步建立原生生态。

## 当前状态

当前版本是 **v0.12 研究原型**，包含：

- 生成和加载 Ed25519 本地身份密钥；
- 生成 X25519 临时密钥并计算共享秘密；
- 使用 ChaCha20-Poly1305 演示消息加密与解密；
- 从 DNS TXT 记录读取 `psn-key`；
- 一个最小化的本地 CLI 演示。
- PSN Drive本地Vault、加密分块、去重、版本和恢复CLI。

尚未实现：

- 经过认证的握手协议与正式密钥派生；
- 防重放、前向安全会话和密钥轮换；
- NAT 穿透、中继、离线消息与可靠传输；
- 个人数据仓库、应用沙箱和能力授权；
- 安全启动、自动更新和生产级审计；
- 适合真实用户的密钥保护及恢复方案。

**请勿使用当前代码保护真实个人数据，也不要将其暴露到公网。**

## 快速体验

需要 Python 3.10 或更高版本。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python cli.py
```

### PSN Drive 本地文件仓库

当前仓库已经包含首个可运行的PSN Drive程序。它支持初始化Vault、加密分块导入、Vault内去重、不可变版本、导出、软删除、空间统计和完整性校验。

```powershell
# 初始化一个本地Vault
python drive.py --vault D:\MyPsnDrive init

# 导入文件，--path是Vault中的逻辑路径
python drive.py --vault D:\MyPsnDrive import D:\Photos\photo.jpg --path photos/2026/photo.jpg

# 查看文件与空间
python drive.py --vault D:\MyPsnDrive list
python drive.py --vault D:\MyPsnDrive status
python drive.py --vault D:\MyPsnDrive versions photos/2026/photo.jpg

# 恢复导出并验证全部数据块
python drive.py --vault D:\MyPsnDrive export photos/2026/photo.jpg D:\Restore\photo.jpg
python drive.py --vault D:\MyPsnDrive verify

# 设置物理存储配额
python drive.py --vault D:\MyPsnDrive quota 100GiB

# 使用可续传上传会话导入大文件；网络中断后以相同key重跑
python drive.py --vault D:\MyPsnDrive upload-file D:\Videos\demo.mp4 `
  --path videos/demo.mp4 --key device-a-demo-001

# 移入逻辑回收站
python drive.py --vault D:\MyPsnDrive delete photos/2026/photo.jpg
python drive.py --vault D:\MyPsnDrive restore photos/2026/photo.jpg

# 永久清除必须先逻辑删除
python drive.py --vault D:\MyPsnDrive purge photos/2026/photo.jpg
```

上传会话的底层调试命令包括 `begin-upload`、`upload-status`、`upload-chunk`、`commit-upload`、`abort-upload` 和 `cleanup-uploads`。普通本地使用优先选择 `upload-file`。

### v0.5 HTTPS、设备认证与局域网测试

```powershell
# 节点端：生成TLS身份、创建配对载荷并启动HTTPS API
python drive.py --vault D:\MyPsnDrive tls-init --san 192.168.1.20
python drive.py --vault D:\MyPsnDrive pairing-create --url https://192.168.1.20:7780
python drive.py --vault D:\MyPsnDrive serve

# 客户端：生成设备密钥、认领配对码、登录
python drive.py device-keygen D:\PsnDevice\device.key
python drive.py device-claim https://127.0.0.1:7780 CERT_FINGERPRINT PAIRING_CODE "My laptop" D:\PsnDevice\device.key
python drive.py device-login https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID D:\PsnDevice\device.key
```

默认仍只监听回环地址。局域网测试需要显式使用 `serve --host <LAN-IP> --allow-lan`；即使启用HTTPS和证书固定，v0.5仍不得暴露公网。详见 [HTTPS API与设备认证](docs/HTTP_API.md)。

### v0.6 Windows文件夹单向备份

```powershell
python drive.py sync-init `
  D:\PsnDevice\pictures-sync.json `
  D:\Users\Alice\Pictures `
  https://192.168.1.20:7780 `
  CERT_FINGERPRINT DEVICE_ID D:\PsnDevice\device.key `
  --remote-prefix computers/alice-laptop/pictures

python drive.py sync-run D:\PsnDevice\pictures-sync.json
python drive.py sync-status D:\PsnDevice\pictures-sync.json
```

本地删除不会传播到服务器。首版适合作为周期运行的备份任务，不是双向同步盘。详见 [Windows同步客户端](docs/WINDOWS_SYNC.md)。

### v0.7 周期同步与Web文件浏览

```powershell
# 持续运行，每5分钟同步一次；同一目录只允许一个实例
python drive.py sync-watch D:\PsnDevice\pictures-sync.json --interval 300
```

节点服务启动后可访问 `https://127.0.0.1:7780/`。使用 `device-login` 得到的短期令牌连接，即可查看空间、文件列表并下载文件。详见 [Web文件管理界面](docs/WEB_UI.md)。

### v0.8 Web上传、版本与安全删除

Web界面现在支持分块上传、历史版本查看和非破坏性恢复。删除文件需要额外生成一次性管理员动作令牌：

```powershell
python drive.py admin-authorize `
  https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID `
  D:\PsnDevice\device.key file.delete "documents/example.pdf"
```

动作令牌绑定设备、动作和文件路径，默认5分钟失效且只能使用一次。

### v0.9 目录与回收站

Web界面现在按逻辑目录浏览文件，并支持移动、重命名、查看回收站和撤销删除。永久清除需要单独的签名动作令牌：

```powershell
python drive.py admin-authorize `
  https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID `
  D:\PsnDevice\device.key file.purge "documents/example.pdf"
```

`file.delete`与`file.purge`令牌不能互换；永久清除会删除全部历史版本并回收无人引用的数据块。

### v0.10 元数据保护与保留策略

```powershell
python drive.py --vault D:\MyPsnDrive metadata-backup
python drive.py --vault D:\MyPsnDrive metadata-backups

# 默认只预览过期回收站内容
python drive.py --vault D:\MyPsnDrive retention-set 30
python drive.py --vault D:\MyPsnDrive retention-run
python drive.py --vault D:\MyPsnDrive retention-run --apply
```

Schema升级前会自动备份元数据。元数据备份不包含加密文件块和主密钥，不能代替完整灾难备份。详见 [元数据备份与恢复](docs/METADATA_BACKUP.md)。

### v0.11 完整灾难备份与恢复

```powershell
# 创建包含元数据快照、主密钥和全部加密数据块的恢复包
python drive.py --vault D:\MyPsnDrive disaster-backup
python drive.py --vault D:\MyPsnDrive disaster-backups

# 建议输出到Vault硬盘之外
python drive.py --vault D:\MyPsnDrive disaster-backup `
  --destination E:\PsnBackups\psn-drive-full.tar `
  --label before-disk-upgrade

# 恢复到新目录
python drive.py --vault D:\RestoredPsnDrive disaster-restore E:\PsnBackups\psn-drive-full.tar
```

恢复会校验包内清单、每个文件的SHA-256、SQLite完整性，并在恢复后执行Vault `verify`。如果目标目录已经存在 `.psn`，必须显式使用 `--force`，旧 `.psn` 会先保留为安全副本。灾难备份包包含 `.psn/master.key`，当前未额外加密，必须离线妥善保存。详见 [完整灾难备份与恢复](docs/DISASTER_BACKUP.md)。

### v0.12 服务端配置与Windows托管脚本

```powershell
# 生成服务端配置；如果缺少TLS身份，会自动创建
python drive.py --vault D:\MyPsnDrive server-config-init `
  --host 127.0.0.1 --port 7780 --service-name PSNDrive

# 按配置启动服务
python drive.py --vault D:\MyPsnDrive server-run

# 使用证书固定访问 /v1/health
python drive.py --vault D:\MyPsnDrive server-health

# 生成Windows任务计划/WinSW服务包装器脚本
python drive.py --vault D:\MyPsnDrive windows-service-scripts
```

生成文件默认位于 `D:\MyPsnDrive\.psn\service\windows\`。v0.12还不是正式MSI安装器，但已经提供固定的 `.psn/server.json`、服务运行入口、证书固定健康检查、任务计划安装脚本和WinSW配置模板。详见 [服务端部署与Windows服务化原型](docs/SERVER_DEPLOYMENT.md)。

也可以通过 `python -m pip install -e .` 安装开发版本，随后直接使用 `psn-drive` 命令。

本地Vault的 `.psn/master.key` 当前以受文件权限保护的原始密钥形式保存，仅适合开发验证。丢失密钥将无法恢复数据；灾难备份包已经包含该密钥，因此备份包泄露也等同于Vault密钥泄露。生产版本将引入设备密钥封装、恢复材料和更完整的密钥生命周期。

演示会在当前目录创建未加密的 `identity.key`。它只适合本地开发，不能提交到版本库或用于正式身份。

导出用于实验的公钥：

```powershell
python export_pubkey.py
```

DNS TXT 记录的实验格式：

```text
类型: TXT
名称: @
值: psn-key=BASE64_PUBLIC_KEY
```

该记录目前没有防止 DNS 劫持或密钥替换的完整机制，不能独立作为可信身份依据。

## 目标架构

```text
个人身份（密码学根身份）
          │
          ├── 域名与节点发现
          ├── 设备身份与撤销
          ├── 端到端通信
          └── 能力授权
                 │
          统一个人数据层
          ├── 结构化数据
          ├── 对象与媒体
          ├── 数据关系与来源
          └── 应用隔离空间
                 │
          原生应用 / Web 应用 / Windows 兼容舱
```

## 首款产品：PSN Drive

项目首先实现面向DIY用户的自托管个人网盘/NAS替代：备份Windows文件夹、Android照片和用户选择的手机文件，通过个人节点完成查看、同步、版本管理和安全分享。

关键设计文档：

- [产品定义与首版范围](docs/PRODUCT.md)
- [文件与存储架构](docs/STORAGE_ARCHITECTURE.md)
- [文件同步协议](docs/SYNC_PROTOCOL.md)
- [手机照片及应用数据边界](docs/MOBILE_BACKUP.md)
- [首版威胁模型](docs/THREAT_MODEL.md)
- [当前代码实现与限制](docs/CURRENT_IMPLEMENTATION.md)
- [HTTPS API与设备认证](docs/HTTP_API.md)
- [Windows同步客户端](docs/WINDOWS_SYNC.md)
- [Web文件管理界面](docs/WEB_UI.md)
- [元数据备份与恢复](docs/METADATA_BACKUP.md)
- [完整灾难备份与恢复](docs/DISASTER_BACKUP.md)
- [服务端部署与Windows服务化原型](docs/SERVER_DEPLOYMENT.md)
- [长期公开架构](docs/architecture.md)
- [研发路线图](ROADMAP.md)

## 安全边界

PSN 的目标不是承诺“永远无法攻破”，而是通过隔离、最小权限、加密、审计和恢复限制入侵后的损失。任何安全功能在经过威胁建模、测试和独立审计之前，都不应被视为生产级能力。

发现安全问题时，请不要在公开 Issue 中披露利用细节，参见 [安全策略](SECURITY.md)。

## 参与项目

项目目前优先讨论：威胁模型、身份生命周期、授权语义、数据模型、兼容迁移和最小可验证原型。提交代码或设计建议前请阅读 [贡献指南](CONTRIBUTING.md)。

## 许可证

当前仓库尚未声明开源许可证。在许可证确定前，公开可见不等于允许复制、修改或分发。计划贡献代码前，请先与项目维护者确认许可策略。
