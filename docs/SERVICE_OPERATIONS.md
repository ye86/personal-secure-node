# 服务日志、诊断包与服务生命周期（v0.13-v0.14）

v0.13补齐服务端长期运行所需的基础运维能力：单实例运行锁、服务日志、运行状态和脱敏诊断包。v0.14继续补充启动前预检、进程存活识别、陈旧状态清理和本机停止命令。

## 单实例运行锁

`server-run` 启动时会创建并持有：

```text
.psn/run/server.lock
```

同一个Vault已经有服务进程运行时，第二个 `server-run` 会失败，避免两个HTTPS服务同时写同一个SQLite数据库和Blob Store。

运行状态会写入：

```text
.psn/run/server.json
```

状态文件包含：

- 进程ID；
- 启动时间；
- PSN Drive版本。

注意：锁是运行期保护，不是权限系统。正式生产服务仍需要最小权限账户、服务管理器和崩溃恢复策略。

## 服务日志

默认 `server-run` 会把 stdout/stderr 写入：

```text
.psn/logs/server.log
```

日志达到约5 MiB后，下次启动会自动轮转为带时间戳的旧日志。

调试时可以使用前台模式：

```powershell
python drive.py --vault D:\MyPsnDrive server-run --foreground
```

前台模式仍然获取服务锁，但日志输出保留在控制台。

## 服务状态

```powershell
python drive.py --vault D:\MyPsnDrive server-status
```

输出包括：

- Vault路径；
- 数据库Schema版本；
- 锁文件状态；
- 日志文件大小；
- 存储统计；
- 服务监听配置。

v0.14会根据状态文件中的PID判断服务进程是否仍在运行。如果状态文件存在但PID已经不存在，`server-status` 会标记为陈旧状态。

## 启动前预检

```powershell
python drive.py --vault D:\MyPsnDrive server-preflight
```

预检会检查：

- 服务配置是否有效；
- Vault主密钥和元数据库是否存在；
- TLS证书和私钥是否存在；
- `run`、`logs`、`diagnostics` 目录是否可写；
- 当前是否已有服务进程运行；
- 服务未运行时，监听端口是否可绑定。

预检失败时命令返回非零退出码，适合被安装脚本或服务包装器调用。

## 停止服务

```powershell
python drive.py --vault D:\MyPsnDrive server-stop
```

`server-stop` 会读取 `.psn/run/server.json` 中的PID，并向该本机进程发送终止信号。它只适合停止由当前用户/服务账户启动的本机 `server-run` 进程。

可选参数：

```powershell
python drive.py --vault D:\MyPsnDrive server-stop --timeout 15
python drive.py --vault D:\MyPsnDrive server-stop --cleanup-stale
```

`--cleanup-stale` 只清理已经不存在的进程状态文件，不会停止任何运行中的服务。

## 诊断包

```powershell
python drive.py --vault D:\MyPsnDrive server-diagnostics
```

默认输出到：

```text
.psn/diagnostics/
```

诊断包是 `.zip` 文件，包含：

- `manifest.json`；
- `service-status.json`；
- `server-config-redacted.json`；
- `metadata-summary.json`；
- `logs/server-tail.log`；
- `README.txt`。

诊断包故意不包含：

- `.psn/master.key`；
- `.psn/tls.key`；
- `.psn/blobs/`；
- 设备私钥；
- 访问令牌。

诊断包可以帮助排查安装、端口、空间和服务状态问题，但它仍可能包含文件数量、路径统计、节点URL、证书指纹和日志内容。公开分享前仍应人工检查。

## Windows脚本变化

`windows-service-scripts` 现在额外生成：

```text
collect-diagnostics.ps1
```

用于在Windows服务器上快速生成诊断包：

```powershell
PowerShell -ExecutionPolicy Bypass -File D:\MyPsnDrive\.psn\service\windows\collect-diagnostics.ps1
```

## 当前限制

- `server-stop` 当前是本机PID级停止，不是完整的Windows服务控制管理器集成；
- 没有Windows事件日志集成；
- 没有崩溃报告上传；
- 没有多实例跨用户可见性审计；
- 日志中仍可能包含本地路径和错误上下文。

v0.14的目标不是一次性做成企业级服务管理，而是先把家庭服务器“可长期运行、可排错、不易误开两个实例、能被本机脚本安全停下”的底座打牢。
