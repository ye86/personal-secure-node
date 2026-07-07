# 服务端部署与Windows服务化原型（v0.12）

v0.12把PSN Drive服务端从“手工运行 `serve` 命令”推进到“有固定运行配置、健康检查和Windows托管脚本”的阶段。

它还不是正式安装器：

- 没有MSI/EXE图形安装包；
- 没有自动更新；
- 没有专用Windows Service主进程；
- 没有服务恢复策略的完整安全审计。

但它已经能生成稳定的服务配置，并为Windows任务计划程序或WinSW这类服务包装器提供可重复使用的启动入口。

## 初始化服务配置

```powershell
python drive.py --vault D:\MyPsnDrive init
python drive.py --vault D:\MyPsnDrive server-config-init `
  --host 127.0.0.1 `
  --port 7780 `
  --service-name PSNDrive
```

配置文件保存到：

```text
D:\MyPsnDrive\.psn\server.json
```

如果还没有TLS身份，`server-config-init` 会自动创建 `.psn/tls.crt` 和 `.psn/tls.key`，并把证书SHA-256指纹写入配置。

局域网测试示例：

```powershell
python drive.py --vault D:\MyPsnDrive server-config-init `
  --host 192.168.1.20 `
  --port 7780 `
  --allow-lan `
  --url https://192.168.1.20:7780 `
  --san 192.168.1.20 `
  --service-name PSNDrive
```

默认仍然建议只绑定 `127.0.0.1`。绑定局域网地址必须显式传入 `--allow-lan`。

## 查看配置

```powershell
python drive.py --vault D:\MyPsnDrive server-config-show
```

输出包含：

- Vault路径；
- 监听地址和端口；
- 设备访问URL；
- 证书指纹；
- 服务名称。

## 按配置运行服务

```powershell
python drive.py --vault D:\MyPsnDrive server-run
```

也可以指定配置文件：

```powershell
python drive.py server-run --config D:\MyPsnDrive\.psn\server.json
```

`server-run` 会读取配置中的Vault路径、监听地址、端口和LAN开关，然后启动HTTPS API。它适合被任务计划、WinSW、NSSM或未来的正式安装器调用。

## 健康检查

```powershell
python drive.py --vault D:\MyPsnDrive server-health
```

健康检查会使用配置中的证书指纹访问 `/v1/health`。如果服务证书被替换或连接到错误节点，检查会失败。

## 生成Windows托管脚本

```powershell
python drive.py --vault D:\MyPsnDrive windows-service-scripts
```

默认输出到：

```text
D:\MyPsnDrive\.psn\service\windows\
```

包含：

- `psn-drive-service-run.ps1`：服务启动入口；
- `install-startup-task.ps1`：注册开机启动任务；
- `uninstall-startup-task.ps1`：卸载开机启动任务；
- `winsw-service.xml`：WinSW服务包装器配置模板。

当前推荐先使用任务计划程序原型：

```powershell
PowerShell -ExecutionPolicy Bypass -File D:\MyPsnDrive\.psn\service\windows\install-startup-task.ps1
```

卸载：

```powershell
PowerShell -ExecutionPolicy Bypass -File D:\MyPsnDrive\.psn\service\windows\uninstall-startup-task.ps1
```

任务计划方式不是最终形态，但足够验证家庭服务器重启后自动拉起PSN Drive服务。

## WinSW模板

`winsw-service.xml` 用于后续接入 [WinSW](https://github.com/winsw/winsw) 这类Windows服务包装器。v0.12只生成配置，不下载、不安装第三方二进制文件。

如果用户自行放置WinSW可执行文件，可以基于该XML注册真正的Windows Service。正式安装器阶段应内置签名的服务包装器或改写原生服务入口。

## 当前安全边界

- 服务配置文件不包含访问令牌或设备私钥；
- `.psn/tls.key` 和 `.psn/master.key` 仍在Vault控制目录中，依赖操作系统权限保护；
- 生成的PowerShell脚本适合本地管理员使用，尚未做签名发布；
- 任务计划以当前安装用户/管理员上下文运行，正式产品应使用最小权限服务账户；
- `server-run` 没有热更新、优雅升级和多实例锁；
- 恢复灾难备份前应先停止服务。

v0.12的价值是把服务端运行方式固定下来。下一步可以继续做真正的Windows服务安装器、最小权限账户、日志目录、升级/卸载流程和图形化安装向导。
