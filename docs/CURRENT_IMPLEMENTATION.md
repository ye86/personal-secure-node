# 当前代码实现（v0.15）

本文记录已经落地的代码，避免把长期架构与当前能力混淆。

## 可运行功能

- 初始化单用户本地Vault；
- 以4 MiB默认大小读取文件分块；
- 使用Vault专属带密钥摘要生成Chunk ID；
- 使用HKDF从Vault主密钥派生分块标识密钥和加密密钥；
- 使用ChaCha20-Poly1305及随机Nonce加密每个Chunk；
- 在单个Vault内复用相同Chunk；
- 使用SQLite保存文件、不可变版本、Chunk引用和事件；
- 事务性发布文件版本；
- 导出时逐块认证并验证完整文件摘要；
- 逻辑删除、空间统计和全量Chunk校验；
- 历史版本列表、指定版本导出及恢复为新版本；
- 回收站恢复、永久清除和无引用Chunk回收；
- 物理Blob容量配额；
- 可续传上传会话、固定分块与乱序上传；
- 创建和提交幂等、冲突重试检测；
- 上传取消、超时和孤立Blob清理；
- 一次性设备配对码和Ed25519设备公钥登记；
- 一次性挑战签名及短期作用域令牌；
- 设备列表、撤销及关联令牌撤销；
- 仅回环监听的文件、下载和上传HTTP API；
- 节点自签名TLS身份和SHA-256证书指纹；
- HTTPS强制、客户端证书固定和显式LAN绑定；
- 可供本地二维码渲染的 `psn://pair` 配对载荷；
- 按来源与接口分类的进程内限速；
- Windows目录扫描和本地SQLite同步状态；
- HTTPS挑战登录、证书固定和可续传文件上传；
- 稳定幂等键、内容变更检测和单文件故障隔离；
- 本地删除仅标记missing，不传播服务器删除；
- 基于操作系统文件锁的同步单实例保护；
- `sync-watch` 周期运行与Ctrl+C安全退出；
- 无外部资源的只读Web文件浏览和下载界面；
- Web安全响应头、严格CSP和内存令牌；
- Web分块上传、历史版本查看和非破坏性版本恢复；
- 设备签名的管理员动作挑战与一次性动作令牌；
- 动作令牌的设备、动作、资源、有效期和单次使用绑定；
- 逻辑目录逐层浏览和面包屑式上级导航；
- 文件移动与重命名的事务元数据更新；
- 回收站列表、撤销删除和永久清除；
- 独立的 `file.purge` 设备签名动作权限；
- 可保留的显式空目录与自动父目录登记；
- 最多100项、支持路径互换的事务性批量移动；
- Schema升级前自动元数据备份和SHA-256清单；
- 手动元数据备份、完整性校验、恢复前保险及回滚；
- 回收站保留期预览和显式执行；
- 完整灾难备份包，包含元数据快照、主密钥、TLS身份和全部加密Blob；
- 灾难备份包内文件SHA-256清单和包级SHA-256侧车清单；
- 灾难恢复时校验tar路径安全、文件摘要、SQLite完整性和Schema版本；
- 恢复后自动打开Vault并执行Chunk解密校验；
- 覆盖已有Vault时先保留 `.psn.restore-safety-*` 安全副本；
- 服务端运行配置 `.psn/server.json`；
- `server-run` 按配置启动HTTPS API；
- 使用证书固定的 `server-health` 健康检查；
- Windows任务计划启动脚本、卸载脚本和WinSW配置模板生成；
- 服务端单实例运行锁 `.psn/run/server.lock`；
- 默认服务日志 `.psn/logs/server.log` 和启动时大小轮转；
- `server-status` 运行状态、锁、日志和存储摘要；
- 不含主密钥、TLS私钥和Blob数据的 `server-diagnostics` 诊断包；
- Windows诊断收集脚本 `collect-diagnostics.ps1`；
- `server-preflight` 启动前检查配置、TLS、目录可写性、运行状态和端口；
- `server-status` 标记状态文件PID是否仍在运行及是否陈旧；
- `server-stop` 按本机PID停止 `server-run` 进程或清理陈旧状态；
- 结构化服务事件审计日志 `.psn/logs/service-events.jsonl`；
- `server-events` 查看最近服务生命周期事件；
- 诊断包包含服务事件尾部 `logs/service-events-tail.jsonl`；
- Schema 1至5自动迁移到Schema 6；
- Windows、Linux和macOS均可使用的Python CLI。

## 代码结构

```text
drive.py                 CLI入口
psn_drive/
├── cli.py               命令解析和输出
├── crypto.py            密钥派生与认证加密
├── database.py          SQLite结构和连接策略
├── storage.py           加密Blob物理存储
├── vault.py             文件生命周期与事务
└── errors.py            可预期错误类型
tests/test_drive.py       核心自动测试
```

## 数据提交方式

导入时先把加密Chunk写入Blob Store，再通过一个SQLite事务创建Version、Chunk引用并更新当前版本。进程崩溃可能留下未被引用的孤立Chunk，但不会发布一个缺少元数据的半成品版本。后续垃圾回收器负责安全清理孤立Chunk。

## 数据库版本

v0.15仍使用Schema 6。打开旧Schema 1至5仓库时先创建校验元数据备份，再执行迁移。服务端配置、运行锁、状态文件、日志、事件日志和诊断包都保存在Vault控制目录中，不改变数据库Schema。

## 当前安全限制

- `.psn/master.key`与数据保存在同一Vault，仅由操作系统文件权限保护；
- 尚未使用口令、TPM、硬件密钥或设备密钥封装主密钥；
- HTTPS实现尚未经过外部审计，不能暴露公网；
- TLS密钥未使用TPM封装，证书尚无安全轮换流程；
- 设备私钥仍是未加密PEM，尚未接入系统密钥库或硬件保护；
- 尚无根密钥轮换、恢复材料和管理员多设备确认；
- 限速仅在单进程内存中生效，重启后清空；
- 同步客户端尚未注册为Windows系统服务，也没有VSS一致性快照；
- 同步状态库包含路径和内容摘要，目前未加密；
- 尚无上传配额、恶意文件隔离和解析沙箱；
- SQLite元数据尚未单独加密；
- 灾难备份包当前未额外加密，包含主密钥，必须离线妥善保管；
- 灾难备份仍是全量包，尚无增量、自动计划、异地复制和保留策略；
- Windows服务化仍是原型：当前生成任务计划和WinSW模板，不是签名MSI安装器；
- 任务计划脚本默认使用安装时的Python环境，升级Python或移动项目目录后需重新生成；
- 诊断包不包含密钥和Blob，但可能包含路径、节点URL、证书指纹和日志上下文；
- `server-stop` 是本机PID级停止，不是完整Windows服务控制管理器集成；
- 服务事件日志是本地JSONL文件，尚未接入Windows事件日志或防篡改审计链；
- 当前没有Windows事件日志集成和崩溃报告；
- 当前格式可能在正式协议确定前变化。

因此v0.15适合本地开发和架构验证，不适合保存唯一副本或直接暴露公网。主密钥与整块磁盘一起被盗时，当前版本不能提供有效的离线保密保证。

## CLI

```text
psn-drive --vault <directory> init
psn-drive --vault <directory> import <source> [--path <vault-path>]
psn-drive --vault <directory> list [--deleted]
psn-drive --vault <directory> versions <vault-path>
psn-drive --vault <directory> export <vault-path> <destination> [--version <id>]
psn-drive --vault <directory> delete <vault-path>
psn-drive --vault <directory> restore <vault-path>
psn-drive --vault <directory> restore-version <vault-path> <version-id>
psn-drive --vault <directory> purge <vault-path>
psn-drive --vault <directory> quota <bytes|10GB|10GiB|unlimited>
psn-drive --vault <directory> upload-file <source> --path <vault-path> --key <idempotency-key>
psn-drive --vault <directory> begin-upload <vault-path> <size> <idempotency-key>
psn-drive --vault <directory> upload-status <session-id>
psn-drive --vault <directory> upload-chunk <session-id> <ordinal> <source>
psn-drive --vault <directory> commit-upload <session-id>
psn-drive --vault <directory> abort-upload <session-id>
psn-drive --vault <directory> cleanup-uploads
psn-drive --vault <directory> pairing-create
psn-drive --vault <directory> devices
psn-drive --vault <directory> device-revoke <device-id>
psn-drive --vault <directory> serve
psn-drive --vault <directory> tls-init [--san <DNS-or-IP>]
psn-drive sync-init <config> <local-root> <url> <fingerprint> <device-id> <key-file>
psn-drive sync-run <config> [--full-scan]
psn-drive sync-status <config>
psn-drive sync-watch <config> [--interval <seconds>]
psn-drive directory-create <vault-path>
psn-drive batch-move <moves.json>
psn-drive retention-set <days|disabled>
psn-drive retention-run [--apply]
psn-drive metadata-backup
psn-drive metadata-backups
psn-drive metadata-restore <backup.sqlite3>
psn-drive disaster-backup [--destination <backup.tar>] [--label <label>]
psn-drive disaster-backups
psn-drive disaster-restore <backup.tar> [--destination <vault-root>] [--force]
psn-drive server-config-init [--host <host>] [--port <port>] [--allow-lan] [--url <url>]
psn-drive server-config-show [--config <server.json>]
psn-drive server-run [--config <server.json>]
psn-drive server-health [--config <server.json>]
psn-drive server-status [--config <server.json>]
psn-drive server-preflight [--config <server.json>]
psn-drive server-stop [--timeout <seconds>] [--force] [--cleanup-stale]
psn-drive server-diagnostics [--config <server.json>] [--destination <diagnostics.zip>]
psn-drive server-events [--limit <count>]
psn-drive windows-service-scripts [--config <server.json>] [--output <directory>]
psn-drive device-keygen <key-file>
psn-drive device-claim <url> <fingerprint> <code> <name> <key-file>
psn-drive device-login <url> <fingerprint> <device-id> <key-file>
psn-drive admin-authorize <url> <fingerprint> <device-id> <key-file> file.delete <path>
psn-drive --vault <directory> status
psn-drive --vault <directory> verify
psn-drive --vault <directory> gc
```

所有命令当前设计为单机管理命令。未来HTTP服务必须调用同一业务层，不能复制一套绕过事务和权限检查的文件逻辑。

## 下一开发切片

1. 真正的Windows服务安装器、最小权限账户和安全卸载；
2. Windows事件日志、服务控制管理器集成、崩溃报告和诊断包审计；
3. Windows客户端安装器、VSS快照和安全凭据存储；
4. 灾难备份加密、自动计划、保留策略和异地复制；
5. 主密钥和TLS密钥封装及恢复材料。
