# Lytix Auth - Cloudflare Workers + D1

基于 Cloudflare Workers + D1 的轻量级登录认证系统。无需服务器，用户数据存储在 Cloudflare 全球网络。

## 功能

- **注册 / 登录** — 用户名 + 邮箱 + 密码，PBKDF2-SHA256 加密存储
- **邮箱验证** — 注册后生成验证链接（需配置邮件转发或手动发送）
- **会话管理** — JWT Cookie（HttpOnly, 7 天有效, HS256 签名）
- **API 密钥** — 创建/停用密钥，支持 Bearer Token 认证
- **JSON API** — RESTful 端点，支持第三方集成
- **纯黑 UI** — 极简商务风格，无外部依赖

## 项目结构

```
cf-lytix-auth/
├── wrangler.toml       # Cloudflare Workers 配置
├── schema.sql          # D1 数据库建表语句
├── package.json        # 脚本命令
└── src/
    └── index.js        # Worker 完整代码（647 行）
```

## 部署

### 前置条件

- Node.js + npm
- Cloudflare 账号
- 安装 Wrangler CLI: `npm install -g wrangler`

### 部署步骤

```bash
# 1. 登录 Cloudflare
npx wrangler login

# 2. 创建 D1 数据库
npx wrangler d1 create lytix-auth

# 3. 复制输出的 database_id 到 wrangler.toml

# 4. 初始化数据库表
npx wrangler d1 execute lytix-auth --file=schema.sql

# 5. 修改 wrangler.toml 配置
#    JWT_SECRET: 替换为随机字符串
#    SITE_URL: 替换为你的域名

# 6. 部署
npx wrangler deploy

# 7. 打开浏览器访问输出的 workers.dev 域名
```

### 配置文件

```toml
# wrangler.toml（关键配置项）
name = "lytix-auth"

[[d1_databases]]
binding = "DB"
database_name = "lytix-auth"
database_id = "你的数据库 ID"

[vars]
SITE_URL = "https://lytix-auth.xxx.workers.dev"
JWT_SECRET = "随机字符串"
```

## API

### 检查登录状态

```bash
# Session 认证（浏览器自动带 Cookie）
curl https://your-domain.workers.dev/api/status

# Bearer Token 认证
curl https://your-domain.workers.dev/api/status \
  -H "Authorization: Bearer lytx_xxxxxxxxxxxx"
```

### JSON 登录

```bash
curl -X POST https://your-domain.workers.dev/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"123456"}'
```

## 环境变量（wrangler.toml [vars]）

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SITE_URL` | 站点地址（用于验证链接） | 必填 |
| `JWT_SECRET` | JWT 签名密钥（务必改为随机值） | 必填 |

## 数据库（D1）

建表语句见 `schema.sql`，包含两张表：

- **users** — 用户信息、密码哈希、验证状态
- **api_keys** — API 密钥、所属用户、启用状态

## License

MIT
