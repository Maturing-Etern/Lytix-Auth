# Lytix Auth 登录系统

基于 Flask 的轻量级登录认证系统，支持注册、邮箱验证、API 密钥管理、Bearer Token 认证。

## 功能

- **注册 / 登录** — 用户名 + 邮箱 + 密码，密码经 Werkzeug pbkdf2:sha256 哈希存储
- **邮箱验证** — 注册后发送验证链接（QQ SMTP），未验证用户登录被拦截
- **会话管理** — Flask-Login 安全会话，支持"记住我"
- **API 密钥** — 用户可创建/停用密钥，支持 Bearer Token 认证
- **JSON API** — 提供 RESTful 端点，支持第三方程序集成
- **纯黑商务 UI** — 极简黑底白字风格

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python -c "from app import init_db; init_db()"

# 启动
python app.py
# 访问 http://localhost:5000
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask 密钥（生产环境必须更换） | dev 默认值 |
| `DATABASE_URL` | 数据库连接字符串 | `sqlite:///../data/users.db` |
| `SITE_URL` | 站点地址（用于生成验证链接） | `http://localhost:5000` |
| `MAIL_SERVER` | SMTP 服务器 | `smtp.qq.com` |
| `MAIL_PORT` | SMTP 端口 | `587` |
| `MAIL_USERNAME` | SMTP 用户名（QQ 号） | — |
| `MAIL_PASSWORD` | SMTP 授权码（不是登录密码） | — |
| `MAIL_FROM` | 发件人地址 | — |

## API

### 检查登录状态

```bash
# Session 认证
curl https://your-site.com/api/status -b "session=..."

# Bearer Token 认证
curl https://your-site.com/api/status \
  -H "Authorization: Bearer lytx_xxxxxxxx"
```

### 登录（获取 Session）

```bash
curl -X POST https://your-site.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"123456"}'
```

## 部署

### PythonAnywhere + Cloudflare

1. 上传代码到 PythonAnywhere
2. 配置 WSGI 指向 `app`
3. 设置环境变量 `DATABASE_URL` 为绝对路径
4. Reload
5. （可选）在 Cloudflare 添加域名 CNAME 到 PythonAnywhere

详见 `wsgi_config.txt`。

## 项目结构

```
login-app/
├── app.py                # Flask 后端
├── requirements.txt      # 依赖
├── wsgi_config.txt       # PythonAnywhere WSGI 配置
├── static/
│   └── style.css         # 纯黑商务风格
└── templates/
    ├── base.html         # 基础模板（导航栏 + 闪消息）
    ├── index.html        # 首页
    ├── login.html        # 登录页
    ├── register.html     # 注册页
    ├── dashboard.html    # 控制台
    ├── profile.html      # 个人信息
    └── apikeys.html      # API 密钥管理
```

## License

MIT
