# Cloudflare Workers/Pages 多账号用量监控面板

一个基于 Cloudflare Worker + KV 的多账号 Workers/Pages 请求用量监控面板，参考 edgetunnel 项目的用量详情功能扩展而来。

**同时支持 Worker 部署和 Pages 部署。**

## 功能

- **公开概览** - 首页直接显示用量概览，无需登录（账号名称脱敏）
- **多账号管理** - 支持添加多个 Cloudflare 账号，统一监控
- **双认证方式** - Email + Global API Key 或 AccountID + API Token
- **实时用量查询** - 通过 Cloudflare GraphQL API 查询当日 Workers 和 Pages 请求量
- **并发安全** - 独立 KV 存储，多账号同时刷新互不影响
- **可视化面板** - 进度条、颜色分级、汇总统计
- **深色/浅色模式** - 自动跟随系统主题
- **响应式设计** - 适配桌面和移动端
- **初始化引导** - KV 未绑定或密码未设置时自动展示配置引导页

## 部署

### 方式一：wrangler 部署（推荐）

所有配置写在 `wrangler.toml` 中，部署后自动生效。

**1. 创建 KV 命名空间**

```bash
wrangler kv:namespace create "KV"
```

**2. 配置 wrangler.toml**

```toml
# Worker 部署
name = "cf-usage-dashboard"
main = "_worker.js"
compatibility_date = "2025-11-04"

# 或 Pages 部署
# name = "cf-usage-dashboard"
# pages_build_output_dir = "."
# compatibility_date = "2025-11-04"

[[kv_namespaces]]
binding = "KV"
id = "你的KV命名空间ID"

[vars]
ADMIN = "你的管理员密码"
```

> 密码也可以用 `wrangler secret put ADMIN` 设置，避免明文。

**3. 部署**

```bash
# Worker
wrangler deploy

# Pages
wrangler pages deploy .
```

### 方式二：Dashboard 部署

不使用 `wrangler.toml`，在 Dashboard 中手动配置。

1. Dashboard -> Workers & Pages -> 创建 -> Pages -> 上传 `_worker.js`
2. Settings -> Functions -> KV namespace bindings -> 变量名 `KV`
3. Settings -> Environment variables -> `ADMIN` = 你的密码
4. 重新部署生效

> 注意：一旦使用 wrangler 部署过，Dashboard 绑定面板会变为只读。

## 使用

1. 访问部署地址，首页显示公开用量概览
2. 点击右上角「管理后台」弹出登录窗口
3. 输入密码登录后进入管理面板
4. 添加 Cloudflare 账号，刷新用量

## 认证方式说明

### 方式一：Email + Global API Key

- 在 [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) 获取 Global API Key
- 适合个人账号

### 方式二：Account ID + API Token

- Account ID：在 Workers & Pages 概览页右侧
- API Token：创建自定义 Token，需要 `Account Analytics:Read` 权限
- 适合组织账号或最小权限原则

## API 接口

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 公开用量概览页面 |
| `/login` | POST | 登录认证 |
| `/logout` | GET | 登出 |
| `/admin` | GET | 管理面板（需认证） |
| `/api/public/usage` | GET | 公开用量数据（脱敏） |
| `/api/accounts` | GET/POST | 获取/添加账号 |
| `/api/accounts/:id` | PUT/DELETE | 更新/删除账号 |
| `/api/usage/:id` | GET | 查询单个账号用量 |
| `/api/usage/all` | GET | 批量查询所有账号用量 |
| `/api/export` | GET | 导出配置 |
| `/api/import` | POST | 导入配置 |
| `/api/import-env` | POST | 批量导入凭证 |

## KV 数据结构

每个账号独立存储，避免并发覆盖：

```
account:list      -> ["id1", "id2", ...]
account:{id}      -> {账号完整数据}
```

账号数据结构：

```json
{
  "id": "唯一ID",
  "name": "账号名称",
  "Email": "email@example.com",
  "GlobalAPIKey": "...",
  "AccountID": "...",
  "APIToken": "...",
  "createdAt": "2025-01-01T00:00:00.000Z",
  "lastUsage": {
    "success": true,
    "pages": 1234,
    "workers": 5678,
    "total": 6912,
    "max": 100000
  },
  "lastQueryTime": "2025-01-01T12:00:00.000Z"
}
```

## 免费额度

Cloudflare 免费计划每个账号每日 **100,000** 次 Workers/Pages 请求。面板按此额度计算百分比和颜色提示：

- 绿色：< 50%
- 黄色：50% - 70%
- 橙色：70% - 90%
- 红色：> 90%

## 安全说明

- 首页公开显示用量概览，账号名称自动脱敏
- 管理员密码通过环境变量设置，不存储在代码中
- Cookie 认证，SHA-256 加盐哈希
- API 返回的密钥信息均做脱敏处理
- 建议使用 API Token（最小权限）而非 Global API Key
