# Windows文件夹同步客户端（v0.6-v0.16）

## 定位

v0.7提供可由Windows任务计划程序周期运行、或以周期模式持续运行的单向备份客户端：扫描指定本地目录，把新增或修改文件上传到PSN Drive节点。v0.16新增Windows后台同步脚本生成器，用于把已有同步配置安装为任务计划后台任务。

它目前不是双向同步盘，也不是常驻文件系统驱动。删除本地文件不会删除服务器副本，只会在本地状态库中标记为 `missing`。

## 前置条件

1. 节点已完成 `tls-init` 并运行HTTPS服务；
2. Windows设备已生成Ed25519设备密钥；
3. 设备已通过一次性配对码登记，并获得 `device_id`；
4. 客户端持有已人工确认的节点证书指纹。

## 创建配置

配置文件和设备密钥建议放在同步目录之外：

```powershell
python drive.py sync-init `
  D:\PsnDevice\pictures-sync.json `
  D:\Users\Alice\Pictures `
  https://192.168.1.20:7780 `
  CERT_FINGERPRINT `
  DEVICE_ID `
  D:\PsnDevice\device.key `
  --remote-prefix computers/alice-laptop/pictures
```

配置保存节点URL、证书指纹、设备ID和设备密钥路径，不保存访问令牌。访问令牌在每次运行时通过挑战签名取得，并只保存在进程内存中。

## 执行与状态

```powershell
python drive.py sync-run D:\PsnDevice\pictures-sync.json
python drive.py sync-run D:\PsnDevice\pictures-sync.json --full-scan
python drive.py sync-status D:\PsnDevice\pictures-sync.json

# 每5分钟运行一次，Ctrl+C安全退出
python drive.py sync-watch D:\PsnDevice\pictures-sync.json --interval 300
```

普通扫描先比较文件大小和纳秒修改时间；发生变化时计算SHA-256。完整扫描会重新计算哈希，但内容相同的文件不会重复上传。

本地状态保存在同步根目录的 `.psn-sync/state.sqlite3`，该目录不会上传。状态库包含相对路径、大小、修改时间、内容摘要、远程路径和版本ID，目前未加密；它不包含设备私钥或访问令牌。

## 断点续传

上传幂等键由设备ID、远程路径和内容摘要派生。运行中断后重新执行：

- 已提交文件直接返回原版本；
- 未完成文件只上传缺失分块；
- 已过期或取消的会话安全重新打开；
- 同一路径的新内容创建新版本。

## 文件变化与删除

- 上传前后比较大小和修改时间；上传期间变化的文件下次重试；
- 符号链接和目录链接默认跳过，避免越过用户选定目录；
- 本地删除只标记为 `missing`，服务器文件及版本保留；
- 文件移动表现为“旧路径missing + 新路径上传”，内容仍可去重；
- 单个文件失败不会阻止其他文件，命令以非零退出码报告部分失败。

## Windows任务计划建议

可以每15分钟运行一次 `sync-run`，使用当前登录用户，并禁止同一任务并行启动。日志应保存在权限受限目录，命令参数中不能出现访问令牌或私钥正文。

v0.7使用 `.psn-sync/sync.lock` 获取非阻塞操作系统文件锁。同一同步根目录已有任务运行时，第二个实例会立即失败。任务计划程序仍建议禁止并行实例，以减少无意义的启动和日志噪音。

## v0.16后台同步脚本

```powershell
python drive.py windows-sync-scripts D:\PsnDevice\pictures-sync.json
```

默认输出到：

```text
<同步根目录>\.psn-sync\service\windows\
```

生成文件：

- `sync-watch.ps1`：持续运行同步循环；
- `sync-run-once.ps1`：执行一次同步；
- `sync-status.ps1`：查看本地同步状态；
- `install-startup-task.ps1`：注册登录后启动的后台同步任务；
- `install-periodic-task.ps1`：注册周期性单次同步任务；
- `uninstall-task.ps1`：卸载上述任务。

推荐先使用登录后启动的持续同步任务：

```powershell
PowerShell -ExecutionPolicy Bypass -File <同步根目录>\.psn-sync\service\windows\install-startup-task.ps1
```

如果更希望减少常驻进程，可以使用周期任务：

```powershell
PowerShell -ExecutionPolicy Bypass -File <同步根目录>\.psn-sync\service\windows\install-periodic-task.ps1
```

卸载：

```powershell
PowerShell -ExecutionPolicy Bypass -File <同步根目录>\.psn-sync\service\windows\uninstall-task.ps1
```

当前脚本是功能性安装器原型，不是正式GUI安装包。它优先满足“能后台跑起来、能随用户登录启动、能查看状态、能卸载”的v1.0前功能闭环。

## 尚未实现

- GUI安装器和系统托盘状态；
- 文件系统事件监听；
- 服务端到电脑的下载同步；
- 冲突副本用户界面；
- 删除传播和回收站策略；
- Windows凭据管理器或TPM设备密钥保护；
- 带宽、时间段和网络类型策略；
- VSS快照及打开文件的一致性副本；
- 图形化安装程序与自动更新。
