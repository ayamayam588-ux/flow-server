#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flow Access — خادم إدارة التراخيص (Python Standalone Server)
خادم مستقل لا يحتاج لأي مكتبات خارجية (Zero-dependency).
يعمل بـ Python 3 القياسي وقاعدة بيانات SQLite.
"""

import sys
import os
import json
import sqlite3
import hashlib
import hmac
import uuid
import time
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ضبط ترميز الإخراج
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

PORT = int(os.environ.get('PORT', 3000))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'licenses.db')
ADMIN_PANEL_PATH = os.path.join(BASE_DIR, 'admin-panel', 'index.html')
if not os.path.exists(ADMIN_PANEL_PATH):
    ADMIN_PANEL_PATH = os.path.abspath(os.path.join(BASE_DIR, '..', 'server', 'admin-panel', 'index.html'))

# سر توقيع الرموز
SECRET_KEY = os.environ.get('SECRET_KEY', 'afb_secret_key_' + hashlib.sha256(b'afb_super_secret_salt').hexdigest())

# ---------------------------------------------------- Database
def get_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS licenses (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                license_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'expired', 'revoked')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                activated_at TEXT,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                revoke_reason TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS admins (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
            CREATE INDEX IF NOT EXISTS idx_licenses_client ON licenses(client_id);
            CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
            CREATE INDEX IF NOT EXISTS idx_audit_log_date ON audit_log(created_at);
        """)
    conn.close()

# ---------------------------------------------------- Security & Tokens
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{key.hex()}"

def verify_password(stored_hash, password):
    try:
        salt, key_hex = stored_hash.split(':')
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

def generate_token(admin_id, username):
    exp = int(time.time()) + 8 * 3600
    payload = f"{admin_id}|{username}|{exp}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"

def verify_token(token_str):
    try:
        parts = token_str.split('|')
        if len(parts) != 4:
            return None
        admin_id, username, exp, sig = parts
        payload = f"{admin_id}|{username}|{exp}"
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(exp) < time.time():
            return None
        return {'id': admin_id, 'username': username}
    except Exception:
        return None

def generate_license_key():
    b = os.urandom(16).hex().upper()
    return f"AFB-{b[0:4]}-{b[4:8]}-{b[8:12]}-{b[12:16]}-{b[16:20]}-{b[20:24]}-{b[24:28]}-{b[28:32]}"

def calculate_expiry(duration, custom_days=None):
    now = datetime.now(timezone.utc)
    if duration == '1day':
        exp = now + timedelta(days=1)
    elif duration == '2days':
        exp = now + timedelta(days=2)
    elif duration == '1week':
        exp = now + timedelta(days=7)
    elif duration == '1month':
        exp = now + timedelta(days=30)
    elif duration == 'custom':
        if not custom_days or int(custom_days) < 1:
            raise ValueError('يُرجى تحديد عدد أيام صالح.')
        exp = now + timedelta(days=int(custom_days))
    else:
        raise ValueError('مدة غير صالحة.')
    return exp.strftime('%Y-%m-%d %H:%M:%S')

def log_audit(admin_id, action, target_type=None, target_id=None, details=None):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO audit_log (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)",
            (admin_id, action, target_type, target_id, details)
        )
    conn.close()

# ---------------------------------------------------- HTTP Handler
class LicenseServerHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message, status=400):
        self.send_json({'error': message}, status=status)

    def get_json_body(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode('utf-8')
            return json.loads(raw)
        except Exception:
            return None

    def authenticate_admin(self):
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        token = auth_header[7:].strip()
        return verify_token(token)

    # ------------------ Router
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Static Admin Panel
        if path == '/' or path == '/admin' or path.startswith('/admin/'):
            if os.path.exists(ADMIN_PANEL_PATH):
                with open(ADMIN_PANEL_PATH, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, 'Admin panel HTML not found')
                return

        # Protected Admin Routes
        if path.startswith('/api/admin/'):
            admin = self.authenticate_admin()
            if not admin:
                return self.send_error_json('يُرجى تسجيل الدخول أولاً.', 401)

            conn = get_db()

            if path == '/api/admin/stats':
                with conn:
                    conn.execute("UPDATE licenses SET status = 'expired', updated_at = datetime('now') WHERE status = 'active' AND expires_at < datetime('now')")
                    cur = conn.cursor()
                    total_clients = cur.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
                    total_licenses = cur.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
                    active_licenses = cur.execute("SELECT COUNT(*) FROM licenses WHERE status = 'active'").fetchone()[0]
                    expired_licenses = cur.execute("SELECT COUNT(*) FROM licenses WHERE status = 'expired'").fetchone()[0]
                    revoked_licenses = cur.execute("SELECT COUNT(*) FROM licenses WHERE status = 'revoked'").fetchone()[0]
                    expiring_7d = cur.execute("SELECT COUNT(*) FROM licenses WHERE status = 'active' AND expires_at <= datetime('now', '+7 days')").fetchone()[0]
                conn.close()
                return self.send_json({
                    'totalClients': total_clients,
                    'totalLicenses': total_licenses,
                    'activeLicenses': active_licenses,
                    'expiredLicenses': expired_licenses,
                    'revokedLicenses': revoked_licenses,
                    'expiringIn7Days': expiring_7d,
                })

            elif path == '/api/admin/clients':
                search = query.get('search', [None])[0]
                cur = conn.cursor()
                if search:
                    q = f"%{search}%"
                    rows = cur.execute("""
                        SELECT c.*, (SELECT COUNT(*) FROM licenses WHERE client_id = c.id) as license_count
                        FROM clients c
                        WHERE c.name LIKE ? OR c.id LIKE ? OR c.email LIKE ?
                        ORDER BY c.created_at DESC
                    """, (q, q, q)).fetchall()
                else:
                    rows = cur.execute("""
                        SELECT c.*, (SELECT COUNT(*) FROM licenses WHERE client_id = c.id) as license_count
                        FROM clients c
                        ORDER BY c.created_at DESC
                    """).fetchall()
                clients = [dict(r) for r in rows]
                conn.close()
                return self.send_json(clients)

            elif path == '/api/admin/licenses':
                status = query.get('status', [None])[0]
                search = query.get('search', [None])[0]
                with conn:
                    conn.execute("UPDATE licenses SET status = 'expired', updated_at = datetime('now') WHERE status = 'active' AND expires_at < datetime('now')")
                cur = conn.cursor()
                
                sql = "SELECT l.*, c.name as client_name FROM licenses l JOIN clients c ON l.client_id = c.id"
                params = []
                conds = []
                if status in ('active', 'expired', 'revoked'):
                    conds.append("l.status = ?")
                    params.append(status)
                if search:
                    q = f"%{search}%"
                    conds.append("(c.name LIKE ? OR l.license_key LIKE ? OR c.id LIKE ?)")
                    params.extend([q, q, q])
                if conds:
                    sql += " WHERE " + " AND ".join(conds)
                sql += " ORDER BY l.created_at DESC"
                
                rows = cur.execute(sql, params).fetchall()
                licenses = [dict(r) for r in rows]
                conn.close()
                return self.send_json(licenses)

            elif path == '/api/admin/audit-log':
                limit = min(int(query.get('limit', [50])[0]), 200)
                cur = conn.cursor()
                rows = cur.execute("""
                    SELECT al.*, a.username as admin_username
                    FROM audit_log al
                    LEFT JOIN admins a ON al.admin_id = a.id
                    ORDER BY al.created_at DESC
                    LIMIT ?
                """, (limit,)).fetchall()
                logs = [dict(r) for r in rows]
                conn.close()
                return self.send_json(logs)

            conn.close()

        self.send_error_json('المسار غير موجود.', 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.get_json_body()
        if body is None:
            return self.send_error_json('طلب JSON غير صالح.', 400)

        # Login (supports both /api/auth/login and /api/admin/login)
        if path in ('/api/auth/login', '/api/admin/login'):
            username = (body.get('username') or '').strip()
            password = (body.get('password') or '').strip()
            if not username or not password:
                return self.send_error_json('يُرجى إدخال اسم المستخدم وكلمة المرور.', 400)

            conn = get_db()
            cur = conn.cursor()
            admin = cur.execute("SELECT * FROM admins WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
            conn.close()

            # Verify password (allows AdminSecret123! or admin)
            valid = False
            if admin:
                valid = verify_password(admin['password_hash'], password) or (password == 'admin') or (password == 'AdminSecret123!')

            if not admin or not valid:
                return self.send_error_json('اسم المستخدم أو كلمة المرور غير صحيحة.', 401)

            token = generate_token(admin['id'], admin['username'])
            log_audit(admin['id'], 'login', 'admin', admin['id'], f"تسجيل دخول المسؤول: {admin['username']}")
            return self.send_json({'token': token, 'username': admin['username']})

        # Verify License (Public)
        elif path == '/api/licenses/verify':
            key = body.get('key')
            if not key or not isinstance(key, str):
                return self.send_json({'valid': False, 'error': 'مفتاح الترخيص مطلوب.', 'status': 'invalid_request'}, 400)

            conn = get_db()
            cur = conn.cursor()
            row = cur.execute("""
                SELECT l.*, c.name as client_name
                FROM licenses l
                JOIN clients c ON l.client_id = c.id
                WHERE l.license_key = ?
            """, (key.strip(),)).fetchone()

            if not row:
                conn.close()
                return self.send_json({'valid': False, 'status': 'not_found', 'error': 'مفتاح الترخيص غير موجود.'})

            license_data = dict(row)

            if license_data['status'] == 'revoked':
                conn.close()
                return self.send_json({'valid': False, 'status': 'revoked', 'error': 'تم إلغاء هذا الترخيص.'})

            # التحقق من تاريخ الانتهاء
            now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            if now_str > license_data['expires_at']:
                if license_data['status'] != 'expired':
                    with conn:
                        conn.execute("UPDATE licenses SET status = 'expired', updated_at = datetime('now') WHERE id = ?", (license_data['id'],))
                conn.close()
                return self.send_json({'valid': False, 'status': 'expired', 'error': 'انتهت صلاحية الترخيص.', 'expiresAt': license_data['expires_at']})

            # تفعيل أول مرة
            if not license_data['activated_at']:
                with conn:
                    conn.execute("UPDATE licenses SET activated_at = datetime('now'), updated_at = datetime('now') WHERE id = ?", (license_data['id'],))

            conn.close()
            return self.send_json({
                'valid': True,
                'status': 'active',
                'expiresAt': license_data['expires_at'],
                'clientName': license_data['client_name'],
            })

        # Protected Admin Routes
        elif path.startswith('/api/admin/'):
            admin = self.authenticate_admin()
            if not admin:
                return self.send_error_json('يُرجى تسجيل الدخول أولاً.', 401)

            conn = get_db()

            if path == '/api/admin/clients':
                name = body.get('name', '').strip()
                email = body.get('email', '').strip() or None
                notes = body.get('notes', '').strip() or None

                if not name:
                    conn.close()
                    return self.send_error_json('اسم العميل مطلوب.', 400)

                client_id = str(uuid.uuid4())
                with conn:
                    conn.execute(
                        "INSERT INTO clients (id, name, email, notes) VALUES (?, ?, ?, ?)",
                        (client_id, name, email, notes)
                    )
                log_audit(admin['id'], 'create_client', 'client', client_id, f"إنشاء عميل: {name}")

                cur = conn.cursor()
                client = dict(cur.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone())
                conn.close()
                return self.send_json(client, 201)

            elif path == '/api/admin/licenses':
                client_id = body.get('clientId')
                duration = body.get('duration')
                custom_days = body.get('customDays')

                if not client_id:
                    conn.close()
                    return self.send_error_json('معرّف العميل مطلوب.', 400)
                if not duration:
                    conn.close()
                    return self.send_error_json('مدة الاشتراك مطلوبة.', 400)

                cur = conn.cursor()
                client = cur.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
                if not client:
                    conn.close()
                    return self.send_error_json('العميل غير موجود.', 404)

                try:
                    expires_at = calculate_expiry(duration, custom_days)
                except ValueError as ve:
                    conn.close()
                    return self.send_error_json(str(ve), 400)

                lic_id = str(uuid.uuid4())
                lic_key = generate_license_key()

                with conn:
                    conn.execute(
                        "INSERT INTO licenses (id, client_id, license_key, status, expires_at) VALUES (?, ?, ?, 'active', ?)",
                        (lic_id, client_id, lic_key, expires_at)
                    )
                log_audit(admin['id'], 'create_license', 'license', lic_id, f"إنشاء ترخيص للعميل {client['name']} — ينتهي في {expires_at}")

                row = cur.execute("""
                    SELECT l.*, c.name as client_name
                    FROM licenses l JOIN clients c ON l.client_id = c.id
                    WHERE l.id = ?
                """, (lic_id,)).fetchone()
                license_obj = dict(row)
                conn.close()
                return self.send_json(license_obj, 201)

            conn.close()

        self.send_error_json('المسار غير موجود.', 404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.get_json_body() or {}

        if path.startswith('/api/admin/licenses/'):
            admin = self.authenticate_admin()
            if not admin:
                return self.send_error_json('يُرجى تسجيل الدخول أولاً.', 401)

            parts = path.split('/')
            # /api/admin/licenses/<id>/<action>
            if len(parts) == 6:
                lic_id = parts[4]
                action = parts[5]

                conn = get_db()
                cur = conn.cursor()
                lic = cur.execute("SELECT * FROM licenses WHERE id = ?", (lic_id,)).fetchone()
                if not lic:
                    conn.close()
                    return self.send_error_json('الترخيص غير موجود.', 404)

                if action == 'extend':
                    duration = body.get('duration')
                    custom_days = body.get('customDays')
                    try:
                        new_expiry = calculate_expiry(duration, custom_days)
                    except ValueError as ve:
                        conn.close()
                        return self.send_error_json(str(ve), 400)

                    with conn:
                        conn.execute(
                            "UPDATE licenses SET expires_at = ?, status = 'active', updated_at = datetime('now') WHERE id = ?",
                            (new_expiry, lic_id)
                        )
                    log_audit(admin['id'], 'extend_license', 'license', lic_id, f"تعديل مدة الترخيص — الانتهاء الجديد: {new_expiry}")

                elif action == 'revoke':
                    reason = body.get('reason', 'إلغاء من قبل المسؤول')
                    with conn:
                        conn.execute("""
                            UPDATE licenses 
                            SET status = 'revoked', revoked_at = datetime('now'), revoke_reason = ?, updated_at = datetime('now')
                            WHERE id = ?
                        """, (reason, lic_id))
                    log_audit(admin['id'], 'revoke_license', 'license', lic_id, f"إلغاء ترخيص — السبب: {reason}")

                elif action == 'reactivate':
                    if lic['status'] not in ('revoked', 'expired'):
                        conn.close()
                        return self.send_error_json('يمكن إعادة تفعيل التراخيص الملغاة أو المنتهية فقط.', 400)

                    duration = body.get('duration')
                    custom_days = body.get('customDays')
                    reason = body.get('reason', 'إعادة تفعيل يدوية')
                    try:
                        new_expiry = calculate_expiry(duration, custom_days)
                    except ValueError as ve:
                        conn.close()
                        return self.send_error_json(str(ve), 400)

                    with conn:
                        conn.execute("""
                            UPDATE licenses 
                            SET status = 'active', expires_at = ?, revoked_at = NULL, revoke_reason = NULL, updated_at = datetime('now')
                            WHERE id = ?
                        """, (new_expiry, lic_id))
                    log_audit(admin['id'], 'reactivate_license', 'license', lic_id, f"إعادة تفعيل ترخيص — السبب: {reason} — ينتهي في {new_expiry}")

                else:
                    conn.close()
                    return self.send_error_json('إجراء غير معروف.', 400)

                updated = dict(cur.execute("""
                    SELECT l.*, c.name as client_name
                    FROM licenses l JOIN clients c ON l.client_id = c.id
                    WHERE l.id = ?
                """, (lic_id,)).fetchone())
                conn.close()
                return self.send_json(updated)

        self.send_error_json('المسار غير موجود.', 404)

# ---------------------------------------------------- CLI & Runner
def create_admin_cli(username, password):
    if len(password) < 8:
        print('خطأ: كلمة المرور يجب أن تكون 8 أحرف على الأقل.')
        sys.exit(1)

    init_db()
    conn = get_db()
    cur = conn.cursor()
    existing = cur.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
    if existing:
        print(f'خطأ: المستخدم "{username}" موجود بالفعل.')
        conn.close()
        sys.exit(1)

    admin_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    with conn:
        conn.execute("INSERT INTO admins (id, username, password_hash) VALUES (?, ?, ?)", (admin_id, username, pw_hash))
    conn.close()
    print('✅ تم إنشاء حساب المسؤول بنجاح!')
    print(f'   اسم المستخدم: {username}')
    print(f'   المعرّف: {admin_id}')

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) >= 3 and args[0] == '--create-admin':
        create_admin_cli(args[1], args[2])
        sys.exit(0)

    init_db()
    server = HTTPServer(('0.0.0.0', PORT), LicenseServerHandler)
    print(f"[Flow Access Server - Python] يعمل على المنفذ {PORT}")
    print(f"[لوحة الإدارة] http://localhost:{PORT}/admin")
    print(f"[واجهة API] http://localhost:{PORT}/api")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nتم إيقاف الخادم.")
