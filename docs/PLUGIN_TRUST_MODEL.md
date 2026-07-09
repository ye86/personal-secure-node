# 插件、主体与未来AI Skills权限模型（v0.20）

v0.20开始引入插件信任模型。它不是完整插件运行时，也不会执行第三方代码；当前版本只登记“谁发布了什么、声明要访问什么、用户是否信任它”。

## 核心概念

- `Entity`：责任主体，可以是组织、个人、其他用户或未来AI Agent。
- `Artifact`：主体发布的作品，可以是插件、应用、作品或未来AI Skill。
- `Permission`：作品声明需要的能力和资源范围。
- `Sanction`：用户对主体的限制或惩罚，例如封禁某个厂商及其子作品。

插件和未来AI Skills应共享同一套能力模型。区别只在调用者形态：插件通常有页面或后台服务，AI Skill通常由个人助手调度。

## Manifest示例

```json
{
  "kind": "plugin",
  "id": "plugin.example.photos",
  "name": "照片整理示例",
  "version": "0.1.0",
  "entry": "/plugins/example/photos/",
  "publisher": {
    "id": "entity.example.studio",
    "type": "organization",
    "name": "Example Studio",
    "verified": false
  },
  "author": {
    "id": "entity.example.alice",
    "type": "person",
    "name": "Alice",
    "parent": "entity.example.studio"
  },
  "permissions": [
    {"capability": "files.read", "resource": "photos/*", "description": "读取照片目录"},
    {"capability": "files.write", "resource": "albums/*", "description": "写入相册目录"},
    {"capability": "share.create", "resource": "albums/*", "description": "创建相册分享链接"}
  ]
}
```

## 当前已实现

- 注册插件/作品清单；
- 记录发布主体和作者主体；
- 记录权限声明；
- 启用或禁用插件；
- 封禁某个主体及其子作品；
- 解除封禁；
- Web插件中心展示主体关系、权限声明和有效状态。

## 尚未实现

- 插件包下载、签名校验和版本升级；
- 第三方代码执行、进程隔离和沙箱；
- 权限运行时拦截；
- 插件市场联网目录；
- 付费、评分、审核和分发；
- AI Agent调用这些能力。

v0.20的目标是先把用户视角里的“责任主体”和“惩罚权”放进数据模型，避免未来插件市场和AI Skills各做一套权限体系。
