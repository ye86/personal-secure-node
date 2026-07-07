# 元数据备份、迁移与回收站策略（v0.10-v0.11）

## 元数据备份是什么

PSN Drive元数据备份保存SQLite数据库的一致性副本，包括文件路径、版本、分块引用、设备、授权、上传会话和设置。备份通过SQLite Backup API生成，并附带独立JSON清单和SHA-256摘要。

它不包含：

- `.psn/blobs`中的加密文件块；
- `.psn/master.key`主密钥；
- TLS私钥和设备私钥；
- Windows同步客户端状态。

因此元数据备份不是完整灾难备份。完整恢复必须使用 `disaster-backup`，或同时拥有匹配时间点的元数据、Blob Store和主密钥。详见 [完整灾难备份与恢复](DISASTER_BACKUP.md)。

## 自动迁移备份

打开旧Schema仓库时，系统在执行迁移前自动创建标签为 `pre-migration` 的元数据备份。备份位于：

```text
.psn/backups/
```

当前不会自动删除旧备份，应由后续保留策略管理。

## 手动操作

```powershell
python drive.py --vault D:\MyPsnDrive metadata-backup
python drive.py --vault D:\MyPsnDrive metadata-backups
python drive.py --vault D:\MyPsnDrive metadata-restore BACKUP.sqlite3
```

恢复前会依次：

1. 校验JSON清单存在；
2. 校验数据库SHA-256；
3. 执行SQLite `integrity_check`；
4. 拒绝比当前程序更新的Schema；
5. 自动创建 `pre-restore` 当前元数据保险副本；
6. 恢复后重新执行必要的向前迁移。

回滚旧元数据可能使新上传的Blob失去引用，也可能恢复已经撤销的旧状态，因此恢复后必须检查设备列表、运行 `verify` 并审查孤立Blob。正式产品还需要节点停机锁和完整快照协调。

## 回收站保留策略

```powershell
python drive.py --vault D:\MyPsnDrive retention-set 30
python drive.py --vault D:\MyPsnDrive retention-run
python drive.py --vault D:\MyPsnDrive retention-run --apply
python drive.py --vault D:\MyPsnDrive retention-set disabled
```

`retention-run`默认只预览候选文件，不删除任何内容。只有明确传入 `--apply` 才永久清除超过保留期的文件及版本，并回收无人引用的数据块。

CLI保留策略被视为本机管理员操作，不需要Web动作令牌。部署自动任务前，应先连续观察预览结果，并保留独立离线备份。

## 空目录与批量移动

```powershell
python drive.py --vault D:\MyPsnDrive directory-create documents/empty
python drive.py --vault D:\MyPsnDrive batch-move moves.json
```

`moves.json`：

```json
[
  {"source": "inbox/a.txt", "destination": "archive/a.txt"},
  {"source": "inbox/b.txt", "destination": "archive/b.txt"}
]
```

单次允许1至100项。所有源、目标和冲突在同一事务中验证；任一失败则全部回滚。
