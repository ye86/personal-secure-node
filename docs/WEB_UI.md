# Web文件管理界面（v0.9）

## 使用方式

启动节点HTTPS服务后，在浏览器访问节点地址：

```text
https://127.0.0.1:7780/
```

通过设备挑战登录获取短期令牌：

```powershell
python drive.py device-login https://127.0.0.1:7780 `
  CERT_FINGERPRINT DEVICE_ID D:\PsnDevice\device.key
```

把返回的 `access_token` 粘贴到页面。令牌只保存在当前页面的JavaScript内存变量中，不写入Cookie、Local Storage或Session Storage；刷新或关闭页面后需要重新输入。

## 当前能力

- 显示节点连接状态；
- 显示活动文件数、版本数、物理占用和配额；
- 列出当前可见文件、大小和更新时间；
- 使用认证请求下载文件；
- 选择本地文件并分块上传到指定Vault路径；
- 查看历史版本并将历史版本恢复为新的当前版本；
- 使用设备签名的一次性动作令牌将文件移入回收站；
- 按逻辑目录逐层浏览；
- 移动或重命名文件而不复制内容；
- 查看回收站并撤销删除；
- 使用 `file.purge` 动作令牌永久清除全部版本。
- 手动刷新状态。

上传和版本恢复使用普通 `drive:write` 短期令牌。删除需要额外的一次性管理员动作令牌，它绑定当前设备、`file.delete`动作和完整文件路径，默认5分钟失效且只能使用一次。

生成删除动作令牌：

```powershell
python drive.py admin-authorize `
  https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID `
  D:\PsnDevice\device.key file.delete "documents/example.pdf"
```

把返回的 `action_token` 粘贴到删除对话框。即使浏览器短期访问令牌泄露，没有设备私钥签名也不能直接生成删除令牌。

永久清除使用不同动作，不能复用删除令牌：

```powershell
python drive.py admin-authorize `
  https://127.0.0.1:7780 CERT_FINGERPRINT DEVICE_ID `
  D:\PsnDevice\device.key file.purge "documents/example.pdf"
```

## 前端安全边界

- HTML、JavaScript和CSS均由节点本地提供，不加载CDN、字体或第三方统计；
- 禁止内联脚本和外部源，CSP仅允许同源资源及同源API；
- 页面禁止被其他网站嵌入框架；
- 禁用摄像头、麦克风和定位权限；
- API令牌不出现在URL中；
- 管理员动作令牌具有短期、单次、设备和资源绑定；
- 所有API响应及页面资源使用 `no-store`；
- 前端使用 `textContent` 构建文件列表，不把文件名作为HTML执行。

浏览器中的脚本仍可读取内存令牌，因此任何未来引入的第三方脚本、富文本预览或插件都会显著改变威胁模型，必须重新审查。

## 上传限制

Web上传使用4 MiB分块并在当前页面生命周期内复用会话键。网络中断后，在不刷新页面的情况下重新提交同一个文件可以继续；刷新页面后暂不保证找到旧会话，但服务端孤立会话会按过期策略清理。

浏览器无法安全读取其他应用私有文件，用户必须主动选择文件。大文件上传尚无暂停按钮、并行块策略和带宽限制。

## 尚未实现

- 设备签名直接登录浏览器；
- WebAuthn或操作系统通行密钥；
- 空目录的独立创建和保存；
- 批量移动、批量恢复和保留期限策略；
- 图片缩略图及安全媒体预览；
- 浏览器直接调用硬件密钥完成管理员签名；
- 自动刷新令牌和安全退出按钮；
- 完整无障碍及移动设备测试。
