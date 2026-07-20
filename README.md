# Lytix Auth - Cloudflare Pages + D1

基于 Cloudflare Pages + D1 的轻量级登录认证系统。  
GitHub 推送自动部署，用户数据存储在 Cloudflare 全球网络。

## 功能

- **注册 / 登录** — 用户名 + 邮箱 + 密码，PBKDF2-SHA256 加密
- **邮箱验证** — 注册后生成验证链接
- **会话管理** — JWT Cookie（HttpOnly, 7 天有效期）
- **API 密钥** — 创建/停用/掩码显示，带免责声明确认
- **Bearer Token** — 第三方通过 `Authorization: Bearer <key>` 调 API
- **纯黑 UI** — 极简商务风格，全部内联

## 项目结构

```
cf-lytix-auth/
├── functions/
│   └── [[path]].js       # Pages Function（全站路由 + HTML 模板）
├── public/
│   └── index.html        # 静态入口（显示 Loading）
├── schema.sql            # D1 建表语句
├── wrangler.toml         # 本地开发配置
├── package.json          # 脚本
└── README.md
```

## 部署

### 前置条件

- Cloudflare 账号
- GitHub 账号
- 已安装 Node.js + Wrangler CLI（可选，用于本地开发）

### 部署步骤

```bash
# 1. 创建 D1 数据库
npx wrangler d1 create lytix-auth

# 2. 初始化表结构
npx wrangler d1 execute lytix-auth --file=schema.sql
```

### 3. Cloudflare Pages 连接 GitHub

1. Cloudflare Dashboard → **Workers 和 Pages** → **Pages** → **连接到 Git**
2. 授权 GitHub → 选择 `Maturing-Etern/Lytix-Auth` 仓库
3. 分支选择 `Worker`，框架预设选 **None**
4. 构建命令留空，构建输出目录填 `public`
5. 点 **保存并部署**

### 4. 配置 D1 绑定和环境变量

1. Pages 项目 → **设置** → **函数**
2. **D1 数据库绑定** → 添加绑定：
   - 变量名: `DB`
   - 数据库: `lytix-auth`
3. **环境变量** → 添加：
   - `SITE_URL` = `https://你的用户名.lytix-auth.pages.dev`
   - `JWT_SECRET` = `随机字符串`

### 5. 自动部署

以后每次推送 `Worker` 分支到 GitHub，Pages 自动重新部署。

## API

```bash
# 检查登录状态（Bearer Token）
curl https://你的域名.pages.dev/api/status \
  -H "Authorization: Bearer lytx_xxxxxxxxxxxx"

# JSON 登录
curl -X POST https://你的域名.pages.dev/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"123456"}'
```

## License

MIT
