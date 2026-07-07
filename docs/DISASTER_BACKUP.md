# 完整灾难备份与恢复（v0.11）

v0.11新增完整灾难恢复包，用于在重装系统、更换机器或Vault控制目录损坏后恢复PSN Drive节点。

它和 `metadata-backup` 不是一回事：

- 元数据备份只保存SQLite数据库，用于迁移前保险和轻量回滚；
- 灾难备份保存恢复Vault所需的核心控制数据和加密数据块。

## 备份内容

灾难备份包是一个 `.tar` 文件，内部包含：

- `.psn/metadata.sqlite3` 的一致性快照；
- `.psn/master.key` 主密钥；
- `.psn/blobs/` 下的全部加密Chunk；
- 如果存在，也包含 `.psn/tls.crt` 和 `.psn/tls.key`。

备份包不包含：

- Windows同步客户端本地状态；
- 外部任务计划、服务注册信息和安装器配置；
- 位于Vault目录外的设备私钥；
- 旧的元数据备份包和灾难备份包。

因此，生产部署时仍需单独保护客户端设备私钥和同步配置。

## 创建备份

```powershell
python drive.py --vault D:\MyPsnDrive disaster-backup
python drive.py --vault D:\MyPsnDrive disaster-backups
```

默认输出到：

```text
D:\MyPsnDrive\.psn\disaster-backups\
```

也可以指定外部位置：

```powershell
python drive.py --vault D:\MyPsnDrive disaster-backup `
  --destination E:\PsnBackups\psn-drive-full-20260707.tar `
  --label before-disk-upgrade
```

强烈建议把灾难备份复制到Vault所在硬盘之外，例如外接硬盘、另一台NAS或离线介质。只把备份放在同一块硬盘上，无法防止硬盘损坏。

## 恢复到新目录

```powershell
python drive.py --vault D:\RestoredPsnDrive disaster-restore E:\PsnBackups\psn-drive-full-20260707.tar
```

恢复流程会：

1. 检查tar成员路径，拒绝绝对路径和 `..`；
2. 读取包内清单；
3. 校验每个文件的大小和SHA-256；
4. 检查SQLite `integrity_check`；
5. 拒绝比当前程序更新的Schema；
6. 恢复 `.psn` 控制目录；
7. 重新打开Vault并执行 `verify`，确认主密钥能解密被元数据引用的数据块。

## 覆盖已有Vault

如果目标目录已经存在 `.psn`，默认会拒绝恢复：

```powershell
python drive.py --vault D:\MyPsnDrive disaster-restore E:\PsnBackups\psn-drive-full-20260707.tar
```

需要显式使用：

```powershell
python drive.py --vault D:\MyPsnDrive disaster-restore E:\PsnBackups\psn-drive-full-20260707.tar --force
```

`--force` 不会直接删除旧 `.psn`，而是先移动为：

```text
.psn.restore-safety-<timestamp>
```

然后再恢复备份。确认恢复成功且不再需要旧状态后，用户可以手动清理安全副本。

## 当前限制

- 备份包目前未额外加密；它包含 `.psn/master.key`，必须像保险箱钥匙一样保存；
- 备份包未做增量，只适合手动或周期性全量备份；
- 当前没有自动备份计划、保留策略和异地复制；
- 恢复期间没有全局服务停机锁，生产部署工具应先停止节点服务再恢复；
- 备份包格式仍可能在v1.0前调整。

v0.11的意义是先把“能完整恢复”这条生命线打通。后续版本应继续实现备份加密、增量备份、恢复演练报告和安装器中的自动备份策略。
