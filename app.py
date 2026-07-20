#!/usr/bin/env python3
"""
Lytix Auth - 登录系统
Flask + SQLAlchemy + Werkzeug 密码哈希 + Flask-Login 会话管理
支持邮箱验证链接（QQ SMTP）

部署方式：
  - 本地运行: python app.py
  - PythonAnywhere: 上传项目后配置 WSGI 指向 app
  - Railway/Render: 用 gunicorn app:app
"""

import os
import sys
import uuid
import smtplib
import logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from flask import (Flask, render_template, redirect, url_for,
                    request, flash, jsonify, send_from_directory)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ── 日志 ──────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ── App 初始化 ────────────────────────────────────────────────
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'lytix-auth-dev-key-change-in-production'
)

# 数据库
db_url = os.environ.get('DATABASE_URL', 'sqlite:///../data/users.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SMTP 邮件配置（环境变量，不配则邮件功能跳过）
MAIL_CONFIG = {
    'server': os.environ.get('MAIL_SERVER', 'smtp.qq.com'),
    'port': int(os.environ.get('MAIL_PORT', 587)),
    'username': os.environ.get('MAIL_USERNAME', ''),
    'password': os.environ.get('MAIL_PASSWORD', ''),
    'from_addr': os.environ.get('MAIL_FROM', ''),
}
MAIL_ENABLED = bool(MAIL_CONFIG['username'] and MAIL_CONFIG['password'])

# 站点地址（用于生成验证链接）
SITE_URL = os.environ.get('SITE_URL', 'http://localhost:5000')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'
login_manager.login_message_category = 'warning'


# ── 用户模型 ──────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # ── 邮箱验证 ──
    verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(128), nullable=True, index=True)
    verify_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_verify_token(self):
        """生成验证令牌（有效期 24 小时）"""
        self.verify_token = uuid.uuid4().hex
        self.verify_token_expires = datetime.utcnow() + timedelta(hours=24)
        return self.verify_token

    def verify_email(self, token):
        """验证邮箱"""
        if (self.verify_token
                and self.verify_token == token
                and self.verify_token_expires
                and datetime.utcnow() < self.verify_token_expires):
            self.verified = True
            self.verify_token = None
            self.verify_token_expires = None
            return True
        return False

    def __repr__(self):
        return f'<User {self.username}>'


# ── API 密钥模型 ──────────────────────────────────────────────
class ApiKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False, default='未命名密钥')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    owner = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic'))

    @staticmethod
    def generate_key():
        return 'lytx_' + uuid.uuid4().hex + uuid.uuid4().hex[:16]

    def mask(self):
        """显示前 8 位 + 后 4 位，中间隐藏"""
        return self.key[:8] + '*' * 28 + self.key[-4:]

    def __repr__(self):
        return f'<ApiKey {self.name} by user#{self.user_id}>'


def get_user_from_apikey():
    """从请求头 Authorization: Bearer <key> 中提取用户"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    key_value = auth[7:].strip()
    if not key_value:
        return None
    apikey = ApiKey.query.filter_by(key=key_value, is_active=True).first()
    if apikey is None:
        return None
    apikey.last_used_at = datetime.utcnow()
    db.session.commit()
    return apikey.owner


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ── 邮件发送 ──────────────────────────────────────────────────

def send_verify_email(user):
    """发送验证邮件"""
    token = user.verify_token
    verify_url = f'{SITE_URL}/verify?token={token}'

    if not MAIL_ENABLED:
        logger.warning(f'SMTP 未配置，跳过发送验证邮件给 {user.email}')
        logger.warning(f'验证链接: {verify_url}')
        flash(f'开发模式：验证链接 → <a href="{verify_url}" style="color:var(--text-primary)">{verify_url}</a>', 'warning')
        return True  # 不阻塞注册流程

    subject = '请验证你的 Lytix Auth 邮箱'
    body_html = f'''
    <div style="max-width:520px;margin:0 auto;padding:40px 20px;font-family:-apple-system,sans-serif;color:#333">
      <div style="text-align:center;margin-bottom:32px">
        <h1 style="font-size:20px;font-weight:500;letter-spacing:2px;margin:0">LYTIX AUTH</h1>
      </div>
      <p style="font-size:15px;margin-bottom:24px">你好 <strong>{user.username}</strong>，</p>
      <p style="font-size:14px;color:#666;margin-bottom:24px">
        感谢注册！点击下方按钮验证你的邮箱地址：
      </p>
      <div style="text-align:center;margin-bottom:32px">
        <a href="{verify_url}" style="display:inline-block;padding:12px 32px;background:#000;color:#fff;
          text-decoration:none;border-radius:6px;font-size:14px">验证邮箱</a>
      </div>
      <p style="font-size:12px;color:#999;margin-bottom:8px">
        或复制下方链接到浏览器打开：
      </p>
      <p style="font-size:12px;color:#999;word-break:break-all">{verify_url}</p>
      <hr style="border:none;border-top:1px solid #eee;margin:32px 0">
      <p style="font-size:12px;color:#ccc;text-align:center">
        此链接 24 小时内有效。如非本人操作请忽略此邮件。
      </p>
    </div>
    '''

    msg = MIMEText(body_html, 'html', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = MAIL_CONFIG['from_addr']
    msg['To'] = user.email

    try:
        with smtplib.SMTP(MAIL_CONFIG['server'], MAIL_CONFIG['port']) as server:
            server.starttls()
            server.login(MAIL_CONFIG['username'], MAIL_CONFIG['password'])
            server.send_message(msg)
        logger.info(f'验证邮件已发送至 {user.email}')
        return True
    except Exception as e:
        logger.error(f'发送邮件失败: {e}')
        flash(f'邮件发送失败（{e}），但账号已创建。验证链接: {verify_url}', 'warning')
        return False


# ── 初始化数据库 ──────────────────────────────────────────────
def init_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'users.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with app.app_context():
        db.create_all()
        # 兼容旧表：如果缺少新字段就添加
        import sqlalchemy as sa
        inspector = sa.inspect(db.engine)
        try:
            columns = [c['name'] for c in inspector.get_columns('users')]
            with db.engine.connect() as conn:
                if 'verified' not in columns:
                    conn.execute(sa.text('ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT 0'))
                if 'verify_token' not in columns:
                    conn.execute(sa.text('ALTER TABLE users ADD COLUMN verify_token VARCHAR(128)'))
                if 'verify_token_expires' not in columns:
                    conn.execute(sa.text('ALTER TABLE users ADD COLUMN verify_token_expires DATETIME'))
                conn.commit()
        except sa.exc.NoSuchTableError:
            pass  # 新数据库，表已由 create_all 创建


# ── 路由 ───────────────────────────────────────────────────────

import os as _os
_app_dir = _os.path.dirname(_os.path.abspath(__file__))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(_app_dir, 'favicon.png', mimetype='image/png')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('请填写用户名和密码', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('用户名或密码错误', 'danger')
            return render_template('login.html')

        # ── 邮箱验证检查 ──
        if not user.verified:
            flash('邮箱尚未验证，请先检查收件箱完成验证', 'warning')
            return render_template('login.html',
                                   need_verify=True,
                                   verify_email=user.email)

        login_user(user, remember=True)
        user.last_login = datetime.utcnow()
        db.session.commit()

        next_page = request.args.get('next')
        return redirect(next_page or url_for('dashboard'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        errors = []
        if len(username) < 3:
            errors.append('用户名至少 3 个字符')
        if '@' not in email:
            errors.append('请输入有效的邮箱地址')
        if len(password) < 6:
            errors.append('密码至少 6 个字符')
        if password != confirm:
            errors.append('两次密码不一致')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('用户名已被使用', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册', 'danger')
            return render_template('register.html')

        # 创建未验证用户
        user = User(username=username, email=email, verified=False)
        user.set_password(password)
        user.generate_verify_token()
        db.session.add(user)
        db.session.commit()

        # 发送验证邮件
        send_verify_email(user)

        flash('注册成功！请检查邮箱完成验证', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/verify', methods=['GET'])
def verify_email():
    """邮箱验证链接入口"""
    token = request.args.get('token', '').strip()
    if not token:
        flash('验证链接无效', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(verify_token=token).first()
    if user is None:
        flash('验证链接无效或已过期', 'danger')
        return redirect(url_for('login'))

    if user.verify_email(token):
        db.session.commit()
        flash('邮箱验证成功，请登录', 'success')
    else:
        flash('验证链接已过期，请重新发送', 'danger')

    return redirect(url_for('login'))


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    """重新发送验证邮件"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()

        if user and not user.verified:
            user.generate_verify_token()
            db.session.commit()
            send_verify_email(user)
            flash('验证邮件已重新发送，请检查收件箱', 'success')
        else:
            flash('该邮箱未注册或已验证', 'info')

        return redirect(url_for('login'))

    return render_template('resend_verify.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已安全退出', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# ── API 密钥管理 ─────────────────────────────────────────────

@app.route('/settings/apikeys', methods=['GET', 'POST'])
@login_required
def apikeys():
    """API 密钥管理页面：列出 / 创建密钥"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        accepted = request.form.get('disclaimer', '') == 'on'

        if not name:
            flash('请填写密钥名称', 'danger')
            return redirect(url_for('apikeys'))
        if not accepted:
            flash('请阅读并同意免责声明', 'danger')
            return redirect(url_for('apikeys'))

        # 创建密钥
        apikey = ApiKey(
            user_id=current_user.id,
            name=name,
            key=ApiKey.generate_key(),
            is_active=True
        )
        db.session.add(apikey)
        db.session.commit()

        flash(f'密钥已创建！请立即复制：<code style="background:#333;padding:2px 8px;border-radius:4px;user-select:all">{apikey.key}</code>'
              '<br><strong style="color:var(--warning)">关闭此提示后将无法再次查看完整密钥</strong>', 'success')
        return redirect(url_for('apikeys', show=apikey.id))

    keys = ApiKey.query.filter_by(user_id=current_user.id).order_by(ApiKey.created_at.desc()).all()
    show_id = request.args.get('show', type=int)
    fresh_key = None
    if show_id:
        fresh_key = ApiKey.query.get(show_id)

    return render_template('apikeys.html', keys=keys, fresh_key=fresh_key)


@app.route('/settings/apikeys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_apikey(key_id):
    """删除（停用）API 密钥"""
    apikey = ApiKey.query.get_or_404(key_id)
    if apikey.user_id != current_user.id:
        flash('无权操作此密钥', 'danger')
        return redirect(url_for('apikeys'))

    apikey.is_active = False
    db.session.commit()
    flash(f'密钥 "{apikey.name}" 已停用', 'info')
    return redirect(url_for('apikeys'))


# ── API 端点 ──────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    """检查登录状态（支持 session 和 Bearer Token 两种方式）"""
    user = get_user_from_apikey()
    if user is None and current_user.is_authenticated:
        user = current_user

    if user:
        return jsonify({
            'authenticated': True,
            'username': user.username,
            'email': user.email,
            'verified': user.verified
        })
    return jsonify({'authenticated': False})


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': '请求体为空'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({'error': '用户名或密码错误'}), 401

    if not user.verified:
        return jsonify({
            'error': '邮箱未验证',
            'verify_email': user.email
        }), 403

    login_user(user, remember=True)
    user.last_login = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'ok': True,
        'username': user.username,
        'verified': user.verified,
        'token': user.get_id()
    })


# ── 入口 ───────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()

    if not MAIL_ENABLED:
        logger.warning('邮件服务未配置（设置 MAIL_USERNAME + MAIL_PASSWORD 环境变量可启用）')
        logger.warning('未配置邮件时，验证链接会打印在日志中')

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
