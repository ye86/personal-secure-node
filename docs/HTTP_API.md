# HTTPS API与设备配对（v0.5）

## 安全定位

v0.5强制使用HTTPS。默认只绑定 `127.0.0.1`；非回环地址必须显式传入 `--allow-lan`。客户端不信任自签名证书链，而是严格匹配配对载荷中的SHA-256证书指纹。

这仍是局域网实验版本：尚未经过外部审计，也没有公网级DDoS防护、持久化限速和安全反向代理模型，禁止端口映射到公网。

HTTP连接默认在每个响应后关闭，以降低早期解析器处理未消费请求体和长连接状态时的风险。配对、挑战、令牌、普通认证请求和分块上传采用不同限速桶；限速状态仅在进程内保存，重启后清空。

## 启动

```powershell
python drive.py --vault D:\MyPsnDrive tls-init --san 192.168.1.20
python drive.py --vault D:\MyPsnDrive serve
```

默认地址为 `https://127.0.0.1:7780`。局域网实验：

```powershell
python drive.py --vault D:\MyPsnDrive serve --host 192.168.1.20 --allow-lan
```

TLS私钥存放在Vault控制目录中且依赖操作系统文件权限，尚未由TPM或硬件密钥封装。证书默认有效期一年，目前不会自动轮换；重新生成证书会改变指纹，所有设备必须重新确认。

## 设备配对

### 1. 在节点创建一次性配对码

```powershell
python drive.py --vault D:\MyPsnDrive pairing-create --url https://192.168.1.20:7780
```

服务器只保存配对码的SHA-256摘要。配对码默认5分钟失效且只能使用一次。指定URL后命令会返回 `psn://pair` URI，其中包含节点URL、一次性配对码和证书指纹；Web或移动客户端应在本地将该URI渲染成二维码，不能使用会把密钥上传到第三方的在线二维码服务。

### 2. 在客户端生成设备密钥

```powershell
python drive.py device-keygen D:\PsnDevice\device.key
```

设备私钥当前以未加密PEM保存在客户端，并依赖操作系统文件权限；不能上传到仓库、复制给服务器或通过聊天发送。

### 3. 客户端登记设备

```powershell
python drive.py device-claim https://127.0.0.1:7780 CERT_FINGERPRINT PAIRING_CODE "My laptop" D:\PsnDevice\device.key
```

返回 `device_id`。服务器仅保存Ed25519公钥。

### 4. 取得短期访问令牌

```powershell
python drive.py device-login https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID D:\PsnDevice\device.key
```

客户端签署一次性挑战，成功后得到默认15分钟有效的Bearer令牌。服务器只保存令牌摘要。令牌属于敏感信息，不应写入日志或命令历史。

### 5. 撤销

```powershell
python drive.py --vault D:\MyPsnDrive devices
python drive.py --vault D:\MyPsnDrive device-revoke DEVICE_ID
```

设备撤销会同时撤销其全部未过期令牌。

## 端点

| 方法 | 路径 | 认证 | 用途 |
|---|---|---|---|
| GET | `/v1/health` | 无 | 本机健康检查 |
| POST | `/v1/pairings/claim` | 一次性配对码 | 登记设备公钥 |
| POST | `/v1/auth/challenges` | 设备ID | 创建短期挑战 |
| POST | `/v1/auth/tokens` | Ed25519签名 | 换取短期令牌 |
| GET | `/v1/status` | `drive:read` | Vault状态 |
| GET | `/v1/files` | `drive:read` | 文件列表 |
| GET | `/v1/browse?prefix=...` | `drive:read` | 当前逻辑目录视图 |
| GET | `/v1/trash` | `drive:read` | 回收站列表 |
| GET | `/v1/versions?path=...` | `drive:read` | 历史版本列表 |
| GET | `/v1/download?path=...` | `drive:read` | 流式下载当前或指定版本 |
| POST | `/v1/uploads` | `drive:write` | 创建上传会话 |
| GET | `/v1/uploads/{id}` | `drive:write` | 查询上传进度 |
| PUT | `/v1/uploads/{id}/chunks/{ordinal}` | `drive:write` | 上传原始分块 |
| POST | `/v1/uploads/{id}/commit` | `drive:write` | 原子提交版本 |
| POST | `/v1/uploads/{id}/abort` | `drive:write` | 取消上传 |
| POST | `/v1/versions/restore` | `drive:write` | 将历史版本恢复为新版本 |
| POST | `/v1/admin/challenges` | `drive:write` | 创建资源绑定管理员挑战 |
| POST | `/v1/admin/tokens` | 设备签名 | 换取一次性动作令牌 |
| POST | `/v1/files/delete` | `drive:write` + 动作令牌 | 移入回收站 |
| POST | `/v1/files/move` | `drive:write` | 移动或重命名文件 |
| POST | `/v1/files/batch-move` | `drive:write` | 事务性批量移动，最多100项 |
| POST | `/v1/directories` | `drive:write` | 创建可保留的空目录 |
| POST | `/v1/trash/restore` | `drive:write` | 撤销删除 |
| POST | `/v1/trash/purge` | `drive:write` + `file.purge`令牌 | 永久清除全部版本 |

认证请求使用：

```text
Authorization: Bearer ACCESS_TOKEN
```

## 挑战签名格式

设备签署以下ASCII字节，行分隔符固定为 `\n`：

```text
psn-drive-auth-v1
CHALLENGE_ID
NONCE
```

挑战默认2分钟有效且只能成功使用一次。协议文本已带版本，后续不能在不变更版本标识的情况下修改签名格式。

管理员挑战使用：

```text
psn-drive-admin-v1
CHALLENGE_ID
NONCE
ACTION
RESOURCE
```

动作令牌通过 `X-PSN-Action-Token` 请求头提交。它不能替换普通Bearer令牌，也不能用于签名时未声明的动作或资源。

## v0.5尚未具备

- 自动证书轮换和已配对设备确认新指纹；
- 局域网设备发现及二维码图形界面；
- 持久化、跨进程和分布式限速；
- 全局连接数、带宽及磁盘IO限制；
- 每台设备的细粒度Vault/目录权限；
- 令牌刷新和主动单令牌撤销；
- 防代理配置错误的可信转发规则；
- 正式审计日志和安全事件通知。
