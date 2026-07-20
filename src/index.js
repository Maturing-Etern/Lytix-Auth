// ═══════════════════════════════════════════════════════════════
// Lytix Auth - Cloudflare Workers + D1
// ═══════════════════════════════════════════════════════════════

// ── 工具函数 ──────────────────────────────────────────────────

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function uuid() {
  return crypto.randomUUID().replace(/-/g, '')
}

function now() {
  return new Date().toISOString().replace('T', ' ').split('.')[0]
}

function hoursLater(n) {
  const d = new Date()
  d.setHours(d.getHours() + n)
  return d.toISOString().replace('T', ' ').split('.')[0]
}


// ── 密码哈希（Web Crypto PBKDF2） ────────────────────────────

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256)
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)))
  const saltB64 = btoa(String.fromCharCode(...salt))
  return `pbkdf2:sha256:100000:${saltB64}:${hash}`
}

async function verifyPassword(password, stored) {
  const parts = stored.split(':')
  if (parts[0] !== 'pbkdf2' || parts[1] !== 'sha256') return false
  const iterations = parseInt(parts[2])
  const salt = Uint8Array.from(atob(parts[3]), c => c.charCodeAt(0))
  const expectedHash = parts[4]

  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256)
  const actualHash = btoa(String.fromCharCode(...new Uint8Array(bits)))
  return actualHash === expectedHash
}


// ── JWT Session ──────────────────────────────────────────────

async function createJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '')
  const body = btoa(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 * 7 })).replace(/=/g, '')
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${body}`))))).replace(/=/g, '')
  return `${header}.${body}.${sig}`
}

async function verifyJWT(token, secret) {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0)), encoder.encode(`${parts[0]}.${parts[1]}`))
    if (!valid) return null
    const payload = JSON.parse(atob(parts[1]))
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch { return null }
}


// ── 从请求获取用户 ─────────────────────────────────────────

async function getUserFromRequest(request, env) {
  // 1. Cookie session
  const cookie = request.headers.get('Cookie') || ''
  const match = cookie.match(/session=([^;]+)/)
  if (match) {
    const payload = await verifyJWT(match[1], env.JWT_SECRET)
    if (payload && payload.user_id) {
      const user = await env.DB.prepare('SELECT id, username, email, verified, created_at, last_login FROM users WHERE id = ?').bind(payload.user_id).first()
      if (user) return user
    }
  }

  // 2. Bearer Token (API Key)
  const auth = request.headers.get('Authorization') || ''
  if (auth.startsWith('Bearer ')) {
    const key = auth.slice(7).trim()
    if (key) {
      const row = await env.DB.prepare(
        'SELECT u.id, u.username, u.email, u.verified, u.created_at, u.last_login FROM users u INNER JOIN api_keys ak ON ak.user_id = u.id WHERE ak.key = ? AND ak.is_active = 1'
      ).bind(key).first()
      if (row) {
        await env.DB.prepare('UPDATE api_keys SET last_used_at = ? WHERE key = ?').bind(now(), key).run()
        return row
      }
    }
  }

  return null
}

function setSessionCookie(token) {
  return `session=${token}; HttpOnly; Path=/; Max-Age=${86400 * 7}; SameSite=Lax`
}

function clearSessionCookie() {
  return 'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
}


// ── HTML 模板 ──────────────────────────────────────────────

const STYLE = `
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue","Noto Sans SC",sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:#fff;text-decoration:none;border-bottom:1px solid transparent;transition:border-color .2s}
a:hover{border-bottom-color:#fff}
nav{display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:56px;border-bottom:1px solid #333;background:#000;position:sticky;top:0;z-index:100}
.nav-brand{font-size:16px;font-weight:500;letter-spacing:1px}
.nav-links{display:flex;gap:28px;align-items:center;list-style:none;font-size:13px;color:#999}
.nav-links a{color:#999;border-bottom:none;transition:color .2s}
.nav-links a:hover{color:#fff}
.nav-user{font-size:13px;color:#999}
.nav-user span{color:#fff}
.container{max-width:520px;margin:0 auto;padding:80px 20px 40px}
.container-w{max-width:800px;margin:0 auto;padding:60px 20px 40px}
.card{background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:40px}
.card-title{font-size:20px;font-weight:500;margin-bottom:6px;letter-spacing:.5px}
.card-subtitle{color:#999;font-size:13px;margin-bottom:28px}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:12px;color:#999;margin-bottom:6px;letter-spacing:.5px;text-transform:uppercase}
.form-input{width:100%;padding:10px 14px;background:#222;border:1px solid #333;border-radius:8px;color:#fff;font-size:14px;font-family:inherit;outline:none;transition:border-color .2s}
.form-input:focus{border-color:#666}
.form-input::placeholder{color:#666}
.form-actions{margin-top:28px}
.btn{display:inline-flex;align-items:center;justify-content:center;width:100%;padding:11px 20px;background:#fff;color:#000;border:none;border-radius:8px;font-size:14px;font-weight:500;font-family:inherit;cursor:pointer;transition:opacity .2s;letter-spacing:.3px}
.btn:hover{opacity:.85}
.btn-outline{background:transparent;color:#fff;border:1px solid #333}
.btn-outline:hover{border-color:#fff;opacity:1}
.btn-sm{width:auto;padding:7px 16px;font-size:13px}
.alert{padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:20px;border:1px solid transparent}
.alert-danger{background:rgba(231,76,60,.1);border-color:rgba(231,76,60,.3);color:#e74c3c}
.alert-success{background:rgba(46,204,113,.1);border-color:rgba(46,204,113,.3);color:#2ecc71}
.alert-warning{background:rgba(243,156,18,.1);border-color:rgba(243,156,18,.3);color:#f39c12}
.alert-info{background:rgba(52,152,219,.1);border-color:rgba(52,152,219,.3);color:#3498db}
.auth-link{text-align:center;margin-top:20px;font-size:13px;color:#999}
.auth-link a{color:#fff;border-bottom:1px solid transparent}
.auth-link a:hover{border-bottom-color:#fff}
.stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:20px}
.stat-value{font-size:28px;font-weight:500;line-height:1.2}
.stat-label{font-size:12px;color:#999;margin-top:4px}
.profile-field{display:flex;justify-content:space-between;padding:14px 0;border-bottom:1px solid #333;font-size:13px}
.profile-field:last-child{border-bottom:none}
.profile-field .label{color:#999}
.profile-field .value{color:#fff}
.hero{text-align:center;padding:100px 20px 60px}
.hero h1{font-size:36px;font-weight:500;letter-spacing:2px;margin-bottom:12px}
.hero p{color:#999;font-size:15px;max-width:440px;margin:0 auto 36px}
.hero-actions{display:flex;gap:12px;justify-content:center}
.hero-actions .btn{width:auto;min-width:140px}
.footer{text-align:center;padding:40px 20px;color:#666;font-size:12px}
.features{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;max-width:800px;margin:0 auto;padding:0 20px 80px}
.feature{text-align:center;padding:24px}
.feature h3{font-size:14px;font-weight:500;margin-bottom:6px}
.feature p{font-size:12px;color:#999;line-height:1.5}
@media(max-width:640px){
  nav{padding:0 20px}
  .container{padding-top:60px}
  .card{padding:24px}
  .hero h1{font-size:28px}
  .stats-grid{grid-template-columns:1fr}
  .features{grid-template-columns:1fr}
  .hero-actions{flex-direction:column;align-items:center}
  .hero-actions .btn{width:100%}
}
`

function page(title, content, user) {
  const nav = user
    ? `<div class="nav-brand"><a href="/">LYTIX</a></div>
      <ul class="nav-links">
        <li class="nav-user">${escHtml(user.username)}</li>
        <li><a href="/dashboard">控制台</a></li>
        <li><a href="/profile">个人</a></li>
        <li><a href="/settings/apikeys">API 密钥</a></li>
        <li><a href="/logout" style="padding:6px 16px;border:1px solid #333;border-radius:8px;color:#999">登出</a></li>
      </ul>`
    : `<div class="nav-brand"><a href="/">LYTIX</a></div>
      <ul class="nav-links">
        <li><a href="/login">登录</a></li>
        <li><a href="/register">注册</a></li>
      </ul>`

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${escHtml(title)} - Lytix Auth</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%23000'/><text x='16' y='22' text-anchor='middle' font-size='18' font-weight='bold' fill='%23fff' font-family='Arial'>L</text></svg>">
<style>${STYLE}</style></head>
<body>
<nav>${nav}</nav>
<main>${content}</main>
<footer class="footer">&copy; 2026 Lytix Auth System</footer>
</body></html>`
}

function escHtml(s) {
  if (!s) return ''
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function flash(msg, type = 'info') {
  return `<div class="alert alert-${type}">${msg}</div>`
}


// ── 页面模板 ──────────────────────────────────────────────────

function indexPage(user) {
  const btns = user
    ? `<a href="/dashboard" class="btn" style="width:auto;min-width:140px">进入控制台</a>`
    : `<a href="/register" class="btn" style="width:auto;min-width:140px">注册</a>
       <a href="/login" class="btn btn-outline" style="width:auto;min-width:140px">登录</a>`

  return page('首页', `
    <section class="hero">
      <h1>LYTIX AUTH</h1>
      <p>轻量级登录认证系统。基于 Cloudflare Workers + D1 构建。</p>
      <div class="hero-actions">${btns}</div>
    </section>
    <section class="features">
      <div class="feature"><h3>密码哈希</h3><p>PBKDF2-SHA256 加密存储，不保存原文。</p></div>
      <div class="feature"><h3>会话管理</h3><p>JWT 安全会话，支持记住登录状态。</p></div>
      <div class="feature"><h3>API 支持</h3><p>提供 RESTful JSON API + Bearer Token 认证。</p></div>
    </section>`, user)
}

function loginPage(msg, user, needVerify, verifyEmail) {
  let extra = ''
  if (needVerify) extra = `<div class="alert alert-warning">邮箱 <strong>${escHtml(verifyEmail)}</strong> 尚未验证。<a href="/resend-verification" style="border-bottom:1px solid currentColor">重新发送验证</a></div>`

  return page('登录', `
    <div class="container">
      <div class="card">
        <h2 class="card-title">登录</h2>
        <p class="card-subtitle">输入用户名和密码继续</p>
        ${msg || ''}
        ${extra}
        <form method="POST" action="/login">
          <div class="form-group">
            <label for="username">用户名</label>
            <input type="text" id="username" name="username" class="form-input" placeholder="输入用户名" required autocomplete="username">
          </div>
          <div class="form-group">
            <label for="password">密码</label>
            <input type="password" id="password" name="password" class="form-input" placeholder="输入密码" required autocomplete="current-password">
          </div>
          <div class="form-actions"><button type="submit" class="btn">登录</button></div>
        </form>
        <div class="auth-link">没有账号？<a href="/register">注册</a></div>
      </div>
    </div>`, user)
}

function registerPage(msg, user) {
  return page('注册', `
    <div class="container">
      <div class="card">
        <h2 class="card-title">注册</h2>
        <p class="card-subtitle">创建新账号以使用系统</p>
        ${msg || ''}
        <form method="POST" action="/register">
          <div class="form-group">
            <label for="username">用户名</label>
            <input type="text" id="username" name="username" class="form-input" placeholder="至少 3 个字符" required minlength="3" autocomplete="username">
          </div>
          <div class="form-group">
            <label for="email">邮箱</label>
            <input type="email" id="email" name="email" class="form-input" placeholder="your@email.com" required autocomplete="email">
          </div>
          <div class="form-group">
            <label for="password">密码</label>
            <input type="password" id="password" name="password" class="form-input" placeholder="至少 6 个字符" required minlength="6" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label for="confirm">确认密码</label>
            <input type="password" id="confirm" name="confirm" class="form-input" placeholder="再次输入密码" required minlength="6" autocomplete="new-password">
          </div>
          <div class="form-actions"><button type="submit" class="btn">注册</button></div>
        </form>
        <div class="auth-link">已有账号？<a href="/login">登录</a></div>
      </div>
    </div>`, user)
}

function dashboardPage(user) {
  return page('控制台', `
    <div class="container-w">
      <h2 style="font-weight:500;font-size:20px;margin-bottom:6px">控制台</h2>
      <p style="color:#999;margin-bottom:28px;font-size:13px">欢迎回来，${escHtml(user.username)}</p>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">${user.id}</div><div class="stat-label">用户 ID</div></div>
        <div class="stat-card"><div class="stat-value" style="font-size:14px;font-weight:400;color:#999">${user.created_at ? user.created_at.slice(0,10) : '-'}</div><div class="stat-label">注册日期</div></div>
        <div class="stat-card"><div class="stat-value" style="font-size:14px;font-weight:400;color:#999">${user.last_login ? user.last_login.slice(0,16) : '首次登录'}</div><div class="stat-label">上次登录</div></div>
      </div>
      <div class="card" style="margin-bottom:20px">
        <h3 style="font-size:14px;font-weight:500;margin-bottom:16px">账户信息</h3>
        <div class="profile-field"><span class="label">用户名</span><span class="value">${escHtml(user.username)}</span></div>
        <div class="profile-field"><span class="label">邮箱</span><span class="value">${escHtml(user.email)}</span></div>
        <div class="profile-field"><span class="label">邮箱验证</span><span class="value" style="color:${user.verified ? '#2ecc71' : '#e74c3c'}">${user.verified ? '已验证' : '未验证'}</span></div>
        <div class="profile-field"><span class="label">密码</span><span class="value" style="color:#666">● ● ● ● ● ● ● ●</span></div>
      </div>
    </div>`, user)
}

function profilePage(user) {
  return page('个人信息', `
    <div class="container">
      <div class="card">
        <h2 class="card-title">个人信息</h2>
        <p class="card-subtitle">你的账号详情</p>
        <div class="profile-field"><span class="label">用户名</span><span class="value">${escHtml(user.username)}</span></div>
        <div class="profile-field"><span class="label">邮箱</span><span class="value">${escHtml(user.email)}</span></div>
        <div class="profile-field"><span class="label">邮箱验证</span><span class="value" style="color:${user.verified ? '#2ecc71' : '#e74c3c'}">${user.verified ? '已验证' : '未验证'}</span></div>
        <div class="profile-field"><span class="label">注册时间</span><span class="value">${user.created_at || '-'}</span></div>
        <div class="profile-field"><span class="label">上次登录</span><span class="value">${user.last_login || '首次登录'}</span></div>
        <div class="profile-field"><span class="label">账号状态</span><span class="value" style="color:#2ecc71">正常</span></div>
        <div class="form-actions"><a href="/dashboard" class="btn btn-outline btn-sm" style="text-decoration:none">返回控制台</a></div>
      </div>
    </div>`, user)
}

function resendVerifyPage(msg, user) {
  return page('重新发送验证', `
    <div class="container">
      <div class="card">
        <h2 class="card-title">重新发送验证邮件</h2>
        <p class="card-subtitle">输入注册时使用的邮箱地址</p>
        ${msg || ''}
        <form method="POST" action="/resend-verification">
          <div class="form-group">
            <label for="email">邮箱</label>
            <input type="email" id="email" name="email" class="form-input" placeholder="your@email.com" required autocomplete="email">
          </div>
          <div class="form-actions"><button type="submit" class="btn">重新发送</button></div>
        </form>
        <div class="auth-link"><a href="/login">返回登录</a></div>
      </div>
    </div>`, user)
}

async function apikeysPage(user, env, freshKeyId) {
  const keys = await env.DB.prepare('SELECT id, name, key, created_at, last_used_at, is_active FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all()
  const rows = keys.results || []

  let keyList = ''
  for (const k of rows) {
    const masked = k.key.slice(0, 8) + '*'.repeat(28) + k.key.slice(-4)
    const fresh = freshKeyId && freshKeyId == k.id
    const displayKey = fresh ? `<code style="background:#222;padding:2px 6px;border-radius:4px;color:#f39c12;user-select:all">${escHtml(k.key)}</code><span style="color:#e74c3c;margin-left:6px">（请立即复制）</span>` : `<code style="background:#222;padding:2px 6px;border-radius:4px">${escHtml(masked)}</code>`

    keyList += `
      <div style="padding:16px 0;border-bottom:1px solid #333;display:flex;align-items:center;justify-content:space-between;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="font-size:14px;font-weight:500;margin-bottom:4px">
            ${escHtml(k.name)}
            ${!k.is_active ? '<span style="font-size:11px;color:#666;background:#222;padding:2px 8px;border-radius:4px;margin-left:6px">已停用</span>' : ''}
          </div>
          <div style="font-size:12px;color:#999">${displayKey}</div>
          <div style="font-size:11px;color:#666;margin-top:4px">
            创建人: ${escHtml(user.username)} · 创建于 ${k.created_at}
            ${k.last_used_at ? '· 上次使用: ' + k.last_used_at : ''}
          </div>
        </div>
        ${k.is_active ? `<form method="POST" action="/settings/apikeys/${k.id}/delete" onsubmit="return confirm('确定停用？')"><button type="submit" style="padding:6px 12px;border:1px solid #333;border-radius:8px;background:transparent;color:#999;font-size:12px;cursor:pointer;white-space:nowrap">停用</button></form>` : ''}
      </div>`
  }

  if (!keyList) keyList = '<div style="text-align:center;padding:40px 0;color:#666;font-size:13px">暂无 API 密钥，请在上方创建</div>'

  return page('API 密钥', `
    <div class="container-w" style="max-width:680px">
      <div class="card" style="margin-bottom:24px">
        <h2 class="card-title">创建 API 密钥</h2>
        <p class="card-subtitle">密钥可用于第三方服务以 API 方式访问你的账号</p>
        <form method="POST" action="/settings/apikeys" onsubmit="return confirm('创建后请立即复制，关闭后将无法查看。确定创建吗？')">
          <div class="form-group">
            <label for="name">密钥名称</label>
            <input type="text" id="name" name="name" class="form-input" placeholder="例如：Lytix 查分器对接" required>
          </div>
          <div style="background:#222;border:1px solid #333;border-radius:8px;padding:16px;margin-bottom:16px;font-size:12px;line-height:1.7;color:#999">
            <strong style="color:#f39c12;font-size:13px">⚠ 免责声明</strong>
            <ul style="margin:8px 0 0 16px;padding:0">
              <li>API 密钥拥有你账号的完整访问权限</li>
              <li>请勿将密钥泄露给第三方或上传至公开代码仓库</li>
              <li>如发现密钥泄露，请立即在本页面停用该密钥</li>
              <li>本系统不对因密钥泄露造成的损失承担责任</li>
              <li>创建即表示你已阅读并同意以上条款</li>
            </ul>
          </div>
          <div class="form-group" style="margin-bottom:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer;text-transform:none;letter-spacing:0;font-size:13px;color:#fff">
              <input type="checkbox" name="disclaimer" required style="width:16px;height:16px"> 我已阅读并同意免责声明
            </label>
          </div>
          <div class="form-actions"><button type="submit" class="btn">创建密钥</button></div>
        </form>
      </div>
      <div class="card">
        <h2 class="card-title">已有密钥</h2>
        <p class="card-subtitle">共 ${rows.length} 个密钥</p>
        ${keyList}
      </div>
    </div>`, user)
}


// ── 路由处理 ──────────────────────────────────────────────────

export default {
  async fetch(request, env) {

    const url = new URL(request.url)
    const path = url.pathname
    const method = request.method
    const user = await getUserFromRequest(request, env)

    // ── 首页 ──
    if (path === '/' && method === 'GET') {
      return html(indexPage(user))
    }

    // ── 登录 ──
    if (path === '/login') {
      if (user) return redirect('/dashboard')

      if (method === 'POST') {
        const form = await request.formData()
        const username = (form.get('username') || '').trim()
        const password = form.get('password') || ''

        if (!username || !password) return html(loginPage(flash('请填写用户名和密码', 'danger'), user))

        const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
        if (!row || !(await verifyPassword(password, row.password_hash))) {
          return html(loginPage(flash('用户名或密码错误', 'danger'), user))
        }

        if (!row.verified) {
          return html(loginPage('', user, true, row.email))
        }

        const token = await createJWT({ user_id: row.id, username: row.username }, env.JWT_SECRET)
        await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(now(), row.id).run()

        return new Response(null, { status: 302, headers: { 'Location': url.searchParams.get('next') || '/dashboard', 'Set-Cookie': setSessionCookie(token) } })
      }

      return html(loginPage('', user))
    }

    // ── 注册 ──
    if (path === '/register') {
      if (user) return redirect('/dashboard')

      if (method === 'POST') {
        const form = await request.formData()
        const username = (form.get('username') || '').trim()
        const email = (form.get('email') || '').trim()
        const password = form.get('password') || ''
        const confirm = form.get('confirm') || ''

        const errors = []
        if (username.length < 3) errors.push('用户名至少 3 个字符')
        if (!email.includes('@')) errors.push('请输入有效的邮箱地址')
        if (password.length < 6) errors.push('密码至少 6 个字符')
        if (password !== confirm) errors.push('两次密码不一致')
        if (errors.length) return html(registerPage(errors.map(e => flash(e, 'danger')).join(''), user))

        const existingUser = await env.DB.prepare('SELECT id FROM users WHERE username = ? OR email = ?').bind(username, email).first()
        if (existingUser) return html(registerPage(flash('用户名或邮箱已被使用', 'danger'), user))

        const hash = await hashPassword(password)
        const vToken = uuid()
        const expires = hoursLater(24)

        await env.DB.prepare(
          'INSERT INTO users (username, email, password_hash, verified, verify_token, verify_token_expires) VALUES (?, ?, ?, 0, ?, ?)'
        ).bind(username, email, hash, vToken, expires).run()

        const verifyUrl = `${env.SITE_URL}/verify?token=${vToken}`
        console.log(`验证链接: ${verifyUrl}`)

        return html(loginPage(
          flash(`注册成功！开发模式验证链接：<a href="${verifyUrl}" style="color:#fff">${verifyUrl}</a>`, 'success'), user
        ))
      }

      return html(registerPage('', user))
    }

    // ── 邮箱验证 ──
    if (path === '/verify' && method === 'GET') {
      const token = url.searchParams.get('token') || ''
      if (!token) return html(loginPage(flash('验证链接无效', 'danger'), user))

      const row = await env.DB.prepare('SELECT id, verify_token_expires FROM users WHERE verify_token = ?').bind(token).first()
      if (!row) return html(loginPage(flash('验证链接无效或已过期', 'danger'), user))

      if (new Date() > new Date(row.verify_token_expires)) {
        return html(loginPage(flash('验证链接已过期，请重新发送', 'danger'), user))
      }

      await env.DB.prepare('UPDATE users SET verified = 1, verify_token = NULL, verify_token_expires = NULL WHERE id = ?').bind(row.id).run()
      return html(loginPage(flash('邮箱验证成功，请登录', 'success'), user))
    }

    // ── 重新发送验证 ──
    if (path === '/resend-verification') {
      if (method === 'POST') {
        const form = await request.formData()
        const email = (form.get('email') || '').trim()
        const row = await env.DB.prepare('SELECT id, verified FROM users WHERE email = ?').bind(email).first()

        if (row && !row.verified) {
          const vToken = uuid()
          const expires = hoursLater(24)
          await env.DB.prepare('UPDATE users SET verify_token = ?, verify_token_expires = ? WHERE id = ?').bind(vToken, expires, row.id).run()
          const verifyUrl = `${env.SITE_URL}/verify?token=${vToken}`
          console.log(`重新发送验证链接: ${verifyUrl}`)
          return html(loginPage(flash(`验证邮件已重新发送。链接：<a href="${verifyUrl}" style="color:#fff">${verifyUrl}</a>`, 'success'), user))
        }
        return html(loginPage(flash('该邮箱未注册或已验证', 'info'), user))
      }
      return html(resendVerifyPage('', user))
    }

    // ── Dashboard ──
    if (path === '/dashboard') {
      if (!user) return redirect('/login')
      return html(dashboardPage(user))
    }

    // ── 个人页 ──
    if (path === '/profile') {
      if (!user) return redirect('/login')
      return html(profilePage(user))
    }

    // ── 登出 ──
    if (path === '/logout') {
      return new Response(null, { status: 302, headers: { 'Location': '/', 'Set-Cookie': clearSessionCookie() } })
    }

    // ── API 密钥管理 ──
    if (path === '/settings/apikeys') {
      if (!user) return redirect('/login')

      if (method === 'POST') {
        const form = await request.formData()
        const name = (form.get('name') || '').trim()
        const accepted = form.get('disclaimer') === 'on'

        if (!name) return redirect('/settings/apikeys')
        if (!accepted) return redirect('/settings/apikeys')

        const key = 'lytx_' + uuid() + uuid().slice(0, 16)
        const result = await env.DB.prepare(
          'INSERT INTO api_keys (user_id, key, name, is_active) VALUES (?, ?, ?, 1)'
        ).bind(user.id, key, name).run()

        return redirect(`/settings/apikeys?show=${result.meta.last_row_id}`)
      }

      const showId = parseInt(url.searchParams.get('show')) || null
      return await apikeysPage(user, env, showId)
    }

    // ── 删除 API 密钥 ──
    const deleteMatch = path.match(/^\/settings\/apikeys\/(\d+)\/delete$/)
    if (deleteMatch && method === 'POST') {
      if (!user) return redirect('/login')
      const keyId = parseInt(deleteMatch[1])
      const key = await env.DB.prepare('SELECT id, user_id FROM api_keys WHERE id = ?').bind(keyId).first()
      if (key && key.user_id === user.id) {
        await env.DB.prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?').bind(keyId).run()
      }
      return redirect('/settings/apikeys')
    }

    // ── JSON API ──
    if (path === '/api/status' && method === 'GET') {
      if (user) {
        return json({ authenticated: true, username: user.username, email: user.email, verified: !!user.verified })
      }
      return json({ authenticated: false })
    }

    if (path === '/api/login' && method === 'POST') {
      const data = await request.json().catch(() => null)
      if (!data) return json({ error: '请求体为空' }, 400)

      const username = (data.username || '').trim()
      const password = data.password || ''

      if (!username || !password) return json({ error: '用户名和密码不能为空' }, 400)

      const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
      if (!row || !(await verifyPassword(password, row.password_hash))) {
        return json({ error: '用户名或密码错误' }, 401)
      }

      if (!row.verified) return json({ error: '邮箱未验证', verify_email: row.email }, 403)

      await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(now(), row.id).run()
      const token = await createJWT({ user_id: row.id, username: row.username }, env.JWT_SECRET)

      return json({ ok: true, username: row.username, verified: true, token })
    }

    // ── 404 ──
    return new Response('Not Found', { status: 404 })
  }
}


// ── 辅助函数 ──────────────────────────────────────────────────

function html(body) {
  return new Response(body, { headers: { 'Content-Type': 'text/html;charset=utf-8' } })
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json;charset=utf-8' }
  })
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { 'Location': location } })
}
