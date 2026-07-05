#!/usr/bin/env python3
"""IOI City Mall — Halal F&B Tracker with Authentication"""

import sqlite3, hashlib, secrets, time, json, os, re, uuid, subprocess
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template_string, make_response, send_file, abort, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')

# ── Database ────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_key TEXT NOT NULL,
            visit_date DATE NOT NULL,
            UNIQUE(visitor_key, visit_date)
        );
        CREATE INDEX IF NOT EXISTS idx_visit_date ON visitors(visit_date);
        CREATE TABLE IF NOT EXISTS cert_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mall TEXT NOT NULL,
            outlet TEXT NOT NULL,
            lot TEXT,
            image_file TEXT NOT NULL,
            submitter_email TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            myehalal_note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            reviewed_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cert_status ON cert_submissions(status);
        CREATE INDEX IF NOT EXISTS idx_cert_outlet ON cert_submissions(mall, outlet);
        CREATE TABLE IF NOT EXISTS mall_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mall_name TEXT NOT NULL,
            mall_url TEXT,
            submitter_email TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            reviewed_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_mreq_status ON mall_requests(status);
    ''')
    # Migration: add columns if they don't exist
    for col, col_def in [
        ('login_count', 'INTEGER DEFAULT 0'),
        ('is_admin', 'INTEGER DEFAULT 0'),
    ]:
        try:
            db.execute('ALTER TABLE users ADD COLUMN {} {}'.format(col, col_def))
        except sqlite3.OperationalError:
            pass  # Column already exists
    db.commit()
    db.close()

init_db()

# Admin email — set via env or default
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get('ADMIN_EMAIL', 'syafiee@demo.com').split(',') if e.strip()}
# Google sign-in: set GOOGLE_CLIENT_ID to enable (Google-only login). Unset -> password login fallback.
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')

# ── Auth Helpers ────────────────────────────────────────────────

def hash_password(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password, stored):
    salt, h = stored.split(':', 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == h

def generate_token():
    return secrets.token_urlsafe(32)

def set_auth_cookie(response, user_id, email):
    token = generate_token()
    expires = int(time.time()) + 86400 * 7
    payload = "{}:{}:{}".format(user_id, email, expires)
    sig = hashlib.sha256((app.secret_key + payload).encode()).hexdigest()
    cookie_val = payload + ':' + sig
    response.set_cookie('auth', cookie_val, max_age=86400*7, httponly=True, samesite='Lax')
    return response

def read_auth_cookie():
    cookie = request.cookies.get('auth', '')
    try:
        parts = cookie.split(':')
        if len(parts) != 4:
            return None
        uid, email, expires_str, sig = parts
        payload = "{}:{}:{}".format(uid, email, expires_str)
        expected = hashlib.sha256((app.secret_key + payload).encode()).hexdigest()
        if sig != expected:
            return None
        if int(expires_str) < time.time():
            return None
        return (int(uid), email)
    except:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = read_auth_cookie()
        if not auth:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = read_auth_cookie()
        if not auth:
            return redirect(url_for('login_page'))
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (auth[0],)).fetchone()
        db.close()
        if not user or not user['is_admin']:
            return '<body style="background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><div style="text-align:center"><h1 style="color:#f87171">403</h1><p>Akses ditolak. Admin sahaja.</p><a href="/" style="color:#60a5fa">← Dashboard</a></div></body>', 403
        return f(*args, **kwargs)
    return decorated

def track_visitor():
    """Track unique daily visitor by IP+UserAgent hash. Returns counts dict."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')
    visitor_key = hashlib.sha256((ip + '|' + ua).encode()).hexdigest()[:32]
    today = datetime.utcnow().strftime('%Y-%m-%d')
    db = get_db()
    db.execute('INSERT OR IGNORE INTO visitors (visitor_key, visit_date) VALUES (?, ?)',
              (visitor_key, today))
    db.commit()
    # Get counts
    week_start = (datetime.utcnow() - timedelta(days=datetime.utcnow().weekday())).strftime('%Y-%m-%d')
    year_start = datetime.utcnow().strftime('%Y') + '-01-01'
    today_count = db.execute('SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date = ?', (today,)).fetchone()[0]
    week_count = db.execute('SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date >= ?', (week_start,)).fetchone()[0]
    year_count = db.execute('SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date >= ?', (year_start,)).fetchone()[0]
    db.close()
    return {'today': today_count, 'week': week_count, 'year': year_count}

DATA_PATH = os.environ.get('HALAL_DATA', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.json'))

def load_data():
    # multi-mall: {"malls":[{"mall","state","count","summary","outlets":[{name,lot,status,cert_holder}]}]}
    try:
        with open(DATA_PATH, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"malls": [], "generated": "", "source": ""}

# ── Cert upload / review ────────────────────────────────────────
UPLOAD_DIR = os.environ.get('HALAL_UPLOADS', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads'))
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {'jpg', 'jpeg', 'png', 'webp'}
MAX_UPLOAD = 6 * 1024 * 1024  # 6 MB
app.config['MAX_CONTENT_LENGTH'] = 7 * 1024 * 1024  # hard cap sedikit lebih tinggi
# magic-byte signatures (validate content, not just extension)
_SIGS = [b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'RIFF']  # jpg, png, webp(RIFF)


def _ext_ok(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def approved_certs_map():
    """(mall|outlet lower) -> submission row, for approved certs only."""
    db = get_db()
    rows = db.execute("SELECT mall, outlet, myehalal_note, reviewed_at FROM cert_submissions "
                      "WHERE status='approved'").fetchall()
    db.close()
    return {(r['mall'] + '|' + r['outlet']).lower(): dict(r) for r in rows}


def pending_cert_count():
    db = get_db()
    n = db.execute("SELECT COUNT(*) FROM cert_submissions WHERE status='pending'").fetchone()[0]
    db.close()
    return n


def myehalal_lookup(name):
    """Semak silang MyeHalal (kategori PE). Pulangkan nota ringkas. curl (gov TLS)."""
    q = re.sub(r"\s*[-–|(].*$", "", name)
    q = re.sub(r"['’]s?\b", "", q)
    q = re.sub(r"[&+]", " ", q).strip()
    url = ("https://myehalal.halal.gov.my/portal-halal/v1/index.php"
           "?data=ZGlyZWN0b3J5L2luZGV4X2RpcmVjdG9yeTs7Ozs=")
    try:
        args = ["curl", "-sS", "--max-time", "30", "-A", "Mozilla/5.0", "-e", url,
                "--data-urlencode", "negeri=", "--data-urlencode", "category=PE",
                "--data-urlencode", "cari=" + q, "--data-urlencode", "hdnCounter=21",
                "--data-urlencode", "t=", "--data-urlencode", "a=", "--data-urlencode", "ty=", url]
        body = subprocess.run(args, capture_output=True, text=True, timeout=40).stdout
        m = re.search(r"Premis Makanan\((\d+)\)", body)
        cnt = int(m.group(1)) if m else 0
        h = re.search(r'class="company-name">(.*?)</span>', body, re.S)
        holder = re.sub(r"<[^>]*>", "", h.group(1)).strip()[:80] if h else ''
        if cnt > 0:
            return "MyeHalal: {} padanan premis makanan. Pemegang teratas: {}".format(cnt, holder or '-')
        return "MyeHalal: tiada padanan untuk '{}'.".format(q)
    except Exception as e:
        return "MyeHalal: gagal semak ({}).".format(e)

# ── CSS ─────────────────────────────────────────────────────────

CSS = '''
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.auth-body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:32px 24px;width:100%;max-width:400px}
.card h1{font-size:1.3rem;text-align:center;margin-bottom:4px}
.card .sub{font-size:.8rem;color:#94a3b8;text-align:center;margin-bottom:24px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:6px;font-weight:500}
.form-group input{width:100%;padding:10px 14px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:.9rem;outline:none}
.form-group input:focus{border-color:#60a5fa}
.btn{display:block;width:100%;padding:12px;border-radius:10px;font-weight:600;font-size:.9rem;cursor:pointer;border:none;transition:all .2s}
.btn-primary{background:#2563eb;color:#fff}
.btn-primary:hover{background:#1d4ed8}
.alert{padding:10px 14px;border-radius:10px;font-size:.8rem;margin-bottom:16px}
.alert-error{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
.alert-success{background:#14532d;color:#86efac;border:1px solid #166534}
.footer{text-align:center;margin-top:20px;font-size:.78rem;color:#64748b}
.footer a{color:#60a5fa;text-decoration:none}
.footer a:hover{text-decoration:underline}
'''

DASHBOARD_CSS = '''
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
/* ── Premium Header ── */
.app-header{position:sticky;top:0;z-index:50;background:linear-gradient(135deg,rgba(30,41,59,.95),rgba(15,23,42,.98));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(51,65,85,.6);box-shadow:0 4px 24px rgba(0,0,0,.3)}
.header-inner{max-width:820px;margin:0 auto;padding:14px 16px 10px}
.header-row1{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.header-brand{display:flex;flex-direction:column;gap:1px;min-width:0}
.header-brand h2{font-size:1.2rem;font-weight:700;color:#f1f5f9;letter-spacing:-.3px;white-space:nowrap}
.header-brand h2 .icon{color:#60a5fa;margin-right:6px}
.header-brand .subtitle{font-size:.7rem;color:#64748b;white-space:nowrap}
.header-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.header-email{font-size:.73rem;color:#94a3b8;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge-admin-header{display:inline-flex;align-items:center;gap:4px;background:rgba(251,191,36,.15);color:#fbbf24;padding:4px 10px;border-radius:20px;font-size:.68rem;font-weight:600;text-decoration:none;border:1px solid rgba(251,191,36,.25);transition:all .2s}
.badge-admin-header:hover{background:rgba(251,191,36,.25);border-color:rgba(251,191,36,.4)}
.btn-logout{display:inline-flex;align-items:center;gap:4px;padding:6px 11px;border-radius:20px;font-size:.7rem;font-weight:500;color:#f87171;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.2);text-decoration:none;transition:all .2s;cursor:pointer;white-space:nowrap}
.btn-logout:hover{background:rgba(248,113,113,.2);border-color:rgba(248,113,113,.35)}
.header-row2{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.stat-chip{display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;font-size:.68rem;font-weight:500;border:1px solid rgba(51,65,85,.5);background:rgba(30,41,59,.6);white-space:nowrap}
.stat-chip .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.stat-chip .dot.green{background:#4ade80;box-shadow:0 0 6px rgba(74,222,128,.4)}
.stat-chip .dot.blue{background:#60a5fa;box-shadow:0 0 6px rgba(96,165,250,.4)}
.stat-chip .dot.amber{background:#fbbf24;box-shadow:0 0 6px rgba(251,191,36,.4)}
.stat-chip .val{font-weight:700;font-size:.75rem}
.stat-chip .lbl{color:#94a3b8}
.stat-chip.green .val{color:#4ade80}
.stat-chip.blue .val{color:#60a5fa}
.stat-chip.amber .val{color:#fbbf24}
/* ── Container ── */
.container{max-width:800px;margin:0 auto;padding:16px}
header{text-align:center;padding:8px 0 16px}
header h1{font-size:1.3rem;color:#f1f5f9}
header .sub{font-size:.78rem;color:#94a3b8;margin-top:2px}
/* ── Stats Grid (dashboard cards) ── */
.stats{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0}
@media(min-width:500px){.stats{grid-template-columns:1fr 1fr 1fr}}
.stat-card{background:#1e293b;border-radius:12px;padding:14px;text-align:center;border:1px solid #334155}
.stat-card.clickable{cursor:pointer;transition:border-color .15s,transform .1s}
.stat-card.clickable:hover{border-color:#64748b;transform:translateY(-1px)}
.stat-card.active{border-color:#e2e8f0;box-shadow:0 0 0 2px rgba(226,232,240,.35)}
.filter-row{display:flex;gap:8px;align-items:stretch;margin:12px 0}
.filter-row .search-wrap{flex:1;margin:0}
#statusFilter{flex-shrink:0;padding:9px 12px;border-radius:10px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;outline:none;cursor:pointer}
#statusFilter:focus{border-color:#60a5fa}
.stat-card .num{font-size:1.6rem;font-weight:700}
.stat-card .label{font-size:.7rem;color:#94a3b8;margin-top:2px}
.stat-card.blue .num{color:#60a5fa}
.stat-card.green .num{color:#4ade80}
.stat-card.yellow .num{color:#fbbf24}
.stat-card.red .num{color:#f87171}
/* ── Tabs ── */
.tabs{display:flex;gap:0;margin:16px 0 0;border-bottom:2px solid #334155;overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:10px 14px;font-size:.78rem;font-weight:600;color:#94a3b8;cursor:pointer;white-space:nowrap;border-bottom:2px solid transparent;margin-bottom:-2px}
.tab.active{color:#60a5fa;border-bottom-color:#60a5fa}
.search-wrap{margin:12px 0;position:relative}
.search-wrap input{width:100%;padding:9px 12px 9px 34px;border-radius:10px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;outline:none}
.search-wrap input:focus{border-color:#60a5fa}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#64748b;font-size:.85rem}
.panel{display:none}
.panel.active{display:block}
.table-wrap{max-height:60vh;overflow-y:auto;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{position:sticky;top:0;background:#1e293b;color:#94a3b8;font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.4px;padding:10px 8px;text-align:left;border-bottom:2px solid #334155;z-index:1}
td{padding:8px;border-bottom:1px solid #1e293b;vertical-align:middle}
tr:hover td{background:rgba(96,165,250,.08)}
.badge{display:inline-block;padding:3px 7px;border-radius:5px;font-size:.65rem;font-weight:600;white-space:nowrap}
.badge-halal{background:#14532d;color:#4ade80}
.badge-muslim{background:#14532d;color:#86efac}
.badge-no-cert{background:#713f12;color:#fbbf24}
.badge-non-halal{background:#450a0a;color:#f87171}
.badge-alcohol{background:#581c87;color:#d8b4fe}
.badge-retail,.badge-central{background:#1e3a5f;color:#93c5fd}
.badge-boikot{background:#1e3a5f;color:#fbbf24}
.badge-unknown{background:#334155;color:#94a3b8}
.loc{color:#64748b;font-size:.72rem;font-family:monospace}
.name-col{font-weight:500;max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.section-title{font-size:.8rem;font-weight:600;color:#94a3b8;margin:20px 0 6px;padding:8px 12px;background:#1e293b;border-radius:8px}
.notes{background:#1e293b;border-radius:12px;padding:14px;margin-top:16px;font-size:.75rem;color:#94a3b8;line-height:1.7}
.notes strong{color:#e2e8f0}
.tab-count{font-size:.65rem;color:#64748b;margin-left:3px}
/* ── Mobile ── */
@media(max-width:480px){
  .header-brand h2{font-size:1.05rem}
  .header-email{display:none}
  .header-row1{gap:8px}
  .header-row2{gap:6px;margin-top:8px}
  .stat-chip{padding:4px 10px;font-size:.65rem}
  .stat-chip .val{font-size:.7rem}
  .header-inner{padding:12px 12px 10px}
}
@media(max-width:360px){
  .header-brand .subtitle{display:none}
  .stat-chip .lbl{display:none}
}
'''

# ── Pages ───────────────────────────────────────────────────────

LOGIN_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Login — Halal Tracker</title>
<style>''' + CSS + '''</style></head><body class="auth-body">
<div style="position:fixed;top:0;left:0;right:0;background:#1e293b;border-bottom:1px solid #334155;padding:8px 16px;display:flex;justify-content:center;gap:24px;font-size:.7rem;color:#94a3b8;z-index:20;flex-wrap:wrap">
  <span>Hari ini: <strong style="color:#4ade80">{{ visits.today }}</strong></span>
  <span>Minggu ini: <strong style="color:#60a5fa">{{ visits.week }}</strong></span>
  <span>Tahun ini: <strong style="color:#fbbf24">{{ visits.year }}</strong></span>
</div>
<div class="card" style="margin-top:48px">
<h1>Log Masuk</h1><div class="sub">Direktori Halal Mall Malaysia</div>
{% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
{% if google_client_id %}
<div id="g_id_onload" data-client_id="{{ google_client_id }}" data-callback="onGoogle" data-auto_prompt="false"></div>
<div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_blue" data-text="signin_with" data-shape="pill" data-logo_alignment="center" style="display:flex;justify-content:center;margin-top:8px"></div>
<div id="gerr" class="alert alert-error" style="display:none;margin-top:12px"></div>
<div class="footer">Log masuk dengan akaun Google anda.</div>
<script src="https://accounts.google.com/gsi/client" async></script>
<script>
function onGoogle(res){
  fetch('/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:res.credential})})
    .then(function(r){return r.json();}).then(function(j){
      if(j.ok){location.href='/';}
      else{var e=document.getElementById('gerr');e.textContent=j.error||'Gagal log masuk.';e.style.display='block';}
    }).catch(function(){var e=document.getElementById('gerr');e.textContent='Ralat rangkaian.';e.style.display='block';});
}
</script>
{% else %}
<form method="POST">
<div class="form-group"><label>Email</label><input type="email" name="email" placeholder="nama@email.com" required autofocus></div>
<div class="form-group"><label>Password</label><input type="password" name="password" placeholder="(8 aksara)" required></div>
<button class="btn btn-primary" type="submit">Log Masuk</button>
</form>
<div class="footer">Belum ada akaun? <a href="/signup">Daftar sini</a> &middot; <a href="/forgot-password">Lupa password?</a></div>
{% endif %}
</div></body></html>'''

SIGNUP_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Daftar — Halal Tracker</title>
<style>''' + CSS + '''</style></head><body class="auth-body"><div class="card">
<h1>Daftar Akaun</h1><div class="sub">IOI City Mall — Halal F&B Tracker</div>
{% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
{% if success %}<div class="alert alert-success">{{ success|safe }}</div>{% endif %}
<form method="POST">
<div class="form-group"><label>Username</label><input type="text" name="username" placeholder="contoh: Fairuz" required></div>
<div class="form-group"><label>Email</label><input type="email" name="email" placeholder="nama@email.com" required></div>
<div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Minimum 8 aksara" required minlength="8"></div>
<div class="form-group"><label>Sahkan Password</label><input type="password" name="confirm" placeholder="Taip semula password" required></div>
<button class="btn btn-primary" type="submit">Daftar</button>
</form>
<div class="footer">Sudah ada akaun? <a href="/login">Login sini</a></div>
</div></body></html>'''

FORGOT_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Lupa Password — Halal Tracker</title>
<style>''' + CSS + '''</style></head><body class="auth-body"><div class="card">
<h1>Lupa Password</h1><div class="sub">Masukkan email berdaftar untuk reset</div>
{% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
{% if success %}<div class="alert alert-success">{{ success|safe }}</div>{% endif %}
<form method="POST">
<div class="form-group"><label>Email Berdaftar</label><input type="email" name="email" placeholder="nama@email.com" required autofocus></div>
<button class="btn btn-primary" type="submit">Hantar Link Reset</button>
</form>
<div class="footer"><a href="/login">Kembali ke Login</a></div>
</div></body></html>'''

RESET_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Reset Password — Halal Tracker</title>
<style>''' + CSS + '''</style></head><body class="auth-body"><div class="card">
<h1>Reset Password</h1><div class="sub">Pilih password baharu</div>
{% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
{% if success %}<div class="alert alert-success">{{ success|safe }}</div>{% endif %}
{% if token %}
<form method="POST">
<div class="form-group"><label>Password Baharu</label><input type="password" name="password" placeholder="Minimum 8 aksara" required minlength="8"></div>
<div class="form-group"><label>Sahkan Password</label><input type="password" name="confirm" placeholder="Taip semula password" required></div>
<button class="btn btn-primary" type="submit">Tukar Password</button>
</form>
{% endif %}
<div class="footer"><a href="/login">Kembali ke Login</a></div>
</div></body></html>'''

DASHBOARD_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Halal Tracker</title>
<style>''' + DASHBOARD_CSS + '''</style>
<script src="https://cdn.jsdelivr.net/npm/@aejkatappaja/phantom-ui/dist/phantom-ui.cdn.js"></script>
<style>
phantom-ui{display:block;border-radius:12px;overflow:hidden}
phantom-ui::part(shimmer){background:linear-gradient(90deg,transparent 0%,rgba(148,163,184,.06) 40%,rgba(148,163,184,.1) 50%,rgba(148,163,184,.06) 60%,transparent 100%)}
</style></head><body>

<div class="app-header">
  <div class="header-inner">
    <div class="header-row1">
      <div class="header-brand">
        <h2><span class="icon">&#9670;</span>Halal Tracker</h2>
        <span class="subtitle">F&amp;B Halal Dashboard</span>
      </div>
      <div class="header-right">
        <a href="/apa-baru" class="btn-whatsnew">&#10024; Apa baru</a>
        {% if logged_in %}
        {% if is_admin %}{% if pending_certs %}<a href="/admin/certs" class="badge-admin-header" style="background:#78350f;color:#fbbf24">&#128220; {{ pending_certs }} sijil</a>{% endif %}<a href="/admin" class="badge-admin-header">&#9889; Panel Admin</a>{% endif %}
        <span class="header-email" title="{{ user_email }}">{{ user_email }}</span>
        <a href="/logout" class="btn-logout">&#10149; Keluar</a>
        {% else %}
        <a href="/login" class="btn-login">&#128274; Log masuk</a>
        {% endif %}
      </div>
    </div>
    <div class="header-row2">
      <div class="stat-chip green">
        <span class="dot green"></span>
        <span class="val">{{ visits.today }}</span>
        <span class="lbl">Hari ini</span>
      </div>
      <div class="stat-chip blue">
        <span class="dot blue"></span>
        <span class="val">{{ visits.week }}</span>
        <span class="lbl">Minggu ini</span>
      </div>
      <div class="stat-chip amber">
        <span class="dot amber"></span>
        <span class="val">{{ visits.year }}</span>
        <span class="lbl">Tahun ini</span>
      </div>
    </div>
  </div>
</div>

<div class="container">
<header><h1>Direktori Halal Mall Malaysia</h1><div class="sub">Status F&amp;B ikut JAKIM MyeHalal &times; Direktori Mall (Live)</div></header>

<div class="mall-select-wrap"><input id="mallSearch" list="mallList" placeholder="Cari nama mall..." autocomplete="off" onchange="renderMall()"><datalist id="mallList"></datalist></div>

<div class="stats" id="stats"></div>

<div class="filter-row">
  <div class="search-wrap"><span class="search-icon">?</span><input type="text" id="search" placeholder="Cari kedai..." oninput="applyFilters()"></div>
  {% if logged_in %}
  <select id="statusFilter" onchange="setStatus(this.value)">
    <option value="">Semua status</option>
    <option value="certified">Halal (JAKIM)</option>
    <option value="review">Perlu Semak</option>
    <option value="uncertified">Tiada Sijil</option>
    <option value="non_halal">Non-Halal</option>
  </select>
  {% endif %}
</div>

<div class="table-outer{% if not logged_in %} locked{% endif %}">
  <div class="table-wrap"><table><thead><tr><th>Kedai</th><th>Lokasi</th><th>Status</th>{% if logged_in %}<th>Sijil</th>{% endif %}</tr></thead><tbody id="tbody"></tbody></table></div>
  {% if not logged_in %}
  <div class="lock-overlay">
    <div class="lock-card">
      <div class="lock-icon">&#128274;</div>
      <div class="lock-title">Log masuk untuk lihat senarai penuh</div>
      <div class="lock-sub">Status halal setiap kedai tersedia selepas log masuk dengan Google.</div>
      {% if google_client_id %}
      <div id="g_id_onload" data-client_id="{{ google_client_id }}" data-callback="onGoogle" data-auto_prompt="false"></div>
      <div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_blue" data-text="signin_with" data-shape="pill" data-logo_alignment="center" style="display:flex;justify-content:center"></div>
      <div id="gerr" class="cert-msg err" style="display:none;margin-top:10px"></div>
      <script src="https://accounts.google.com/gsi/client" async></script>
      <script>
      function onGoogle(res){
        fetch('/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:res.credential})})
          .then(function(r){return r.json();}).then(function(j){
            if(j.ok){location.reload();}
            else{var e=document.getElementById('gerr');e.textContent=j.error||'Gagal log masuk.';e.style.display='block';}
          }).catch(function(){var e=document.getElementById('gerr');e.textContent='Ralat rangkaian.';e.style.display='block';});
      }
      </script>
      {% else %}
      <a href="/login" class="btn btn-primary lock-btn">Log masuk</a>
      {% endif %}
    </div>
  </div>
  {% endif %}
</div>

<div id="certModal" class="cert-modal"><div class="cert-box">
  <div class="cert-head"><span id="certTitle">Muat naik sijil halal</span><span class="cert-x" onclick="closeCert()">&times;</span></div>
  <p class="cert-sub">Ada sijil halal JAKIM untuk kedai ini? Muat naik gambar sijil. Admin akan semak sebelum dipaparkan.</p>
  <input type="file" id="certFile" accept="image/png,image/jpeg,image/webp">
  <div id="certMsg" class="cert-msg"></div>
  <button class="btn btn-primary" id="certSend" onclick="sendCert()">Hantar untuk semakan</button>
</div></div>

<div class="notes"><strong>Nota:</strong> Status dari portal rasmi JAKIM MyeHalal (kategori Premis Makanan).
<span class="badge b-cert">Halal (JAKIM)</span> ada sijil &middot;
<span class="badge b-review">Perlu Semak</span> ada padanan sijil tapi nama pemegang berbeza &middot;
<span class="badge b-uncert">Tiada Sijil</span> tiada rekod JAKIM (bukan bermaksud haram) &middot;
<span class="badge b-nonhalal">Non-Halal</span> jual khinzir/arak.<br>
Sumber direktori: laman rasmi setiap mall (live).</div>

{% if logged_in %}
<div class="mall-req">
  <div class="mall-req-title">&#127978; Tiada mall dalam senarai?</div>
  <div class="mall-req-sub">Cadangkan mall &mdash; admin akan semak dan tambah ke direktori.</div>
  <input type="text" id="reqName" maxlength="160" placeholder="Nama mall (cth: Mid Valley Megamall)">
  <input type="url" id="reqUrl" maxlength="300" placeholder="Pautan directory (pilihan)">
  <div id="reqMsg" class="cert-msg"></div>
  <button class="btn btn-primary" id="reqBtn" onclick="sendMallReq()">Hantar cadangan</button>
</div>
{% endif %}
</div>

<style>
.mall-select-wrap{margin:14px 0}
#mallSearch{width:100%;padding:10px 12px;border-radius:10px;background:#1e293b;color:#e2e8f0;border:1px solid #334155;font-size:.9rem}
.badge.b-cert{background:#14532d;color:#4ade80}
.badge.b-review{background:#78350f;color:#fbbf24}
.badge.b-uncert{background:#334155;color:#94a3b8}
.badge.b-nonhalal{background:#450a0a;color:#f87171}
.badge.b-verified{background:#134e4a;color:#5eead4;margin-left:4px}
.cert-btn{cursor:pointer;border:1px solid #334155;background:#0f172a;color:#60a5fa;border-radius:8px;padding:3px 8px;font-size:.72rem;white-space:nowrap}
.cert-btn:hover{background:#1e293b}
.cert-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center;padding:16px}
.cert-modal.show{display:flex}
.cert-box{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:22px;max-width:420px;width:100%}
.cert-head{display:flex;justify-content:space-between;align-items:center;font-weight:700;margin-bottom:8px}
.cert-x{cursor:pointer;font-size:1.4rem;color:#94a3b8}
.cert-sub{font-size:.8rem;color:#94a3b8;margin-bottom:14px}
#certFile{width:100%;font-size:.82rem;margin-bottom:12px;color:#e2e8f0}
.cert-msg{font-size:.8rem;margin-bottom:10px;min-height:1em}
.cert-msg.ok{color:#4ade80}.cert-msg.err{color:#f87171}
.btn-login{display:inline-flex;align-items:center;gap:5px;padding:6px 13px;border-radius:20px;font-size:.72rem;font-weight:600;color:#4ade80;background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.25);text-decoration:none;white-space:nowrap}
.btn-login:hover{background:rgba(74,222,128,.2)}
.btn-whatsnew{display:inline-flex;align-items:center;gap:4px;padding:6px 11px;border-radius:20px;font-size:.72rem;font-weight:600;color:#c4b5fd;background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.25);text-decoration:none;white-space:nowrap}
.btn-whatsnew:hover{background:rgba(167,139,250,.2)}
.table-outer{position:relative}
.table-outer.locked .table-wrap{filter:blur(6px);pointer-events:none;user-select:none;max-height:420px;overflow:hidden}
.lock-overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;padding:16px;background:linear-gradient(180deg,rgba(15,23,42,.15),rgba(15,23,42,.75))}
.lock-card{text-align:center;background:rgba(30,41,59,.96);border:1px solid #334155;border-radius:16px;padding:26px 24px;max-width:340px;box-shadow:0 12px 40px rgba(0,0,0,.5)}
.lock-icon{font-size:2rem;margin-bottom:8px}
.lock-title{font-weight:700;font-size:1rem;color:#f1f5f9;margin-bottom:6px}
.lock-sub{font-size:.8rem;color:#94a3b8;margin-bottom:16px;line-height:1.5}
.lock-btn{display:inline-block;text-decoration:none}
.mall-req{margin:18px 0;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:18px}
.mall-req-title{font-weight:700;font-size:1rem;color:#f1f5f9}
.mall-req-sub{font-size:.8rem;color:#94a3b8;margin:4px 0 12px}
.mall-req input{width:100%;padding:9px 12px;margin-bottom:8px;border-radius:9px;background:#0f172a;color:#e2e8f0;border:1px solid #334155;font-size:.85rem}
</style>

<script>
var D = {{ data|tojson }};
var LOGGED_IN = {{ 'true' if logged_in else 'false' }};
var MALLS = D.malls || [];
var APPROVED = new Set({{ approved|tojson }});
var BADGE = {certified:['b-cert','Halal (JAKIM)'],review:['b-review','Perlu Semak'],uncertified:['b-uncert','Tiada Sijil'],non_halal:['b-nonhalal','Non-Halal']};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function badge(s){var b=BADGE[s]||['b-uncert',s];return '<span class="badge '+b[0]+'">'+b[1]+'</span>';}
var search=document.getElementById('mallSearch');
document.getElementById('mallList').innerHTML=MALLS.map(function(m){return '<option value="'+esc(m.mall)+'">'+m.count+' kedai</option>'}).join('');
var curIdx=0;
function mallIndex(){var v=search.value.trim().toLowerCase();for(var i=0;i<MALLS.length;i++){if(MALLS[i].mall.toLowerCase()===v)return i;}return -1;}
// empty the box on every tap (click fires even when already focused) so the FULL list always drops down
search.addEventListener('mousedown',function(){search.value='';});
search.addEventListener('focus',function(){search.value='';});
function renderMall(){
  var i=mallIndex(); if(i>=0)curIdx=i;         // keep last pick if input blank/partial
  var m=MALLS[curIdx]; search.placeholder=m?m.mall:'Cari nama mall...';
  if(!m){document.getElementById('tbody').innerHTML='';document.getElementById('stats').innerHTML='';return;}
  var s=m.summary||{};
  document.getElementById('stats').innerHTML=
    '<div class="stat-card green clickable" data-status="certified"><div class="num">'+(s.certified||0)+'</div><div class="label">Halal (JAKIM)</div></div>'+
    '<div class="stat-card yellow clickable" data-status="review"><div class="num">'+(s.review||0)+'</div><div class="label">Perlu Semak</div></div>'+
    '<div class="stat-card blue clickable" data-status="uncertified"><div class="num">'+(s.uncertified||0)+'</div><div class="label">Tiada Sijil</div></div>'+
    '<div class="stat-card red clickable" data-status="non_halal"><div class="num">'+(s.non_halal||0)+'</div><div class="label">Non-Halal</div></div>';
  syncActiveCard();
  if(!LOGGED_IN){
    // placeholder rows (blurred) so guests see a teaser sized to the real count
    var n=Math.min(m.count||0,12), ph='';
    var fake=['certified','review','uncertified','certified','uncertified','review'];
    for(var j=0;j<n;j++){ph+='<tr><td class="name-col">Restoran '+(j+1)+' Sdn Bhd</td><td class="loc">Lot '+(j+1)+'.0'+((j%9)+1)+'</td><td>'+badge(fake[j%fake.length])+'</td></tr>';}
    document.getElementById('tbody').innerHTML=ph; return;
  }
  var rows=(m.outlets||[]).slice().sort(function(a,b){return a.name.localeCompare(b.name)});
  document.getElementById('tbody').innerHTML=rows.map(function(d,i){
    var key=(m.mall+'|'+d.name).toLowerCase();
    var verified=APPROVED.has(key)?'<span class="badge b-verified">✓ Disahkan</span>':'';
    var btn='<button class="cert-btn" data-i="'+i+'">📷 Sijil</button>';
    return '<tr data-status="'+d.status+'"><td class="name-col" title="'+esc(d.name)+'">'+esc(d.name)+'</td><td class="loc">'+esc(d.lot||'')+'</td><td>'+badge(d.status)+verified+'</td><td>'+btn+'</td></tr>'
  }).join('');
  applyFilters();
}
// ── Penapisan: gabung carian teks + kategori status ──
var curStatus='';
function applyFilters(){
  var q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#tbody tr').forEach(function(r){
    var okText=r.textContent.toLowerCase().indexOf(q)!==-1;
    var okStatus=!curStatus||r.getAttribute('data-status')===curStatus;
    r.style.display=(okText&&okStatus)?'':'none';
  });
}
function setStatus(v){curStatus=v; var sf=document.getElementById('statusFilter'); if(sf)sf.value=v; syncActiveCard(); applyFilters();}
function syncActiveCard(){document.querySelectorAll('#stats .stat-card').forEach(function(c){
  c.classList.toggle('active', !!curStatus && c.getAttribute('data-status')===curStatus);});}
// klik kad stat -> tapis ikut kategori (guest: perlu sign in dulu)
document.getElementById('stats').addEventListener('click',function(e){
  var card=e.target.closest('.stat-card'); if(!card)return;
  if(!LOGGED_IN){document.querySelector('.table-outer').scrollIntoView({behavior:'smooth',block:'center'}); return;}
  var st=card.getAttribute('data-status');
  setStatus(curStatus===st?'':st);   // klik semula kad sama = buang tapisan
});
// ── upload sijil ──
var curOutlet=null;
document.getElementById('tbody').addEventListener('click',function(e){
  var b=e.target.closest('.cert-btn'); if(!b)return;
  var m=MALLS[curIdx]; if(!m)return; var rows=(m.outlets||[]).slice().sort(function(a,b){return a.name.localeCompare(b.name)});
  var d=rows[+b.dataset.i]; if(!d)return;
  curOutlet={mall:m.mall,outlet:d.name,lot:d.lot||''};
  document.getElementById('certTitle').textContent='Sijil halal: '+d.name;
  document.getElementById('certFile').value=''; var msg=document.getElementById('certMsg'); msg.textContent=''; msg.className='cert-msg';
  document.getElementById('certModal').classList.add('show');
});
function closeCert(){document.getElementById('certModal').classList.remove('show');}
function sendCert(){
  var f=document.getElementById('certFile').files[0]; var msg=document.getElementById('certMsg');
  if(!f){msg.textContent='Sila pilih gambar sijil.';msg.className='cert-msg err';return;}
  if(f.size>6*1024*1024){msg.textContent='Fail terlalu besar (max 6MB).';msg.className='cert-msg err';return;}
  var fd=new FormData(); fd.append('mall',curOutlet.mall); fd.append('outlet',curOutlet.outlet); fd.append('lot',curOutlet.lot); fd.append('image',f);
  var btn=document.getElementById('certSend'); btn.disabled=true; btn.textContent='Menghantar...';
  fetch('/submit-cert',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(j){
    btn.disabled=false; btn.textContent='Hantar untuk semakan';
    if(j.ok){msg.textContent='Terima kasih! Sijil dihantar untuk semakan admin.';msg.className='cert-msg ok';setTimeout(closeCert,1800);}
    else{msg.textContent=j.error||'Gagal hantar.';msg.className='cert-msg err';}
  }).catch(function(){btn.disabled=false;btn.textContent='Hantar untuk semakan';msg.textContent='Ralat rangkaian.';msg.className='cert-msg err';});
}
function sendMallReq(){
  var name=document.getElementById('reqName').value.trim(); var msg=document.getElementById('reqMsg');
  if(!name){msg.textContent='Sila isi nama mall.';msg.className='cert-msg err';return;}
  var fd=new FormData(); fd.append('mall_name',name); fd.append('mall_url',document.getElementById('reqUrl').value.trim());
  var btn=document.getElementById('reqBtn'); btn.disabled=true; btn.textContent='Menghantar...';
  fetch('/submit-mall',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(j){
    btn.disabled=false; btn.textContent='Hantar cadangan';
    if(j.ok){msg.textContent='Terima kasih! Cadangan dihantar untuk semakan admin.';msg.className='cert-msg ok';document.getElementById('reqName').value='';document.getElementById('reqUrl').value='';}
    else{msg.textContent=j.error||'Gagal hantar.';msg.className='cert-msg err';}
  }).catch(function(){btn.disabled=false;btn.textContent='Hantar cadangan';msg.textContent='Ralat rangkaian.';msg.className='cert-msg err';});
}
renderMall();  // default: first mall, box stays empty (placeholder shows current)
</script>
</body></html>'''

ADMIN_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Admin — Halal Tracker</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.app-header{position:sticky;top:0;z-index:50;background:linear-gradient(135deg,rgba(30,41,59,.95),rgba(15,23,42,.98));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(51,65,85,.6);box-shadow:0 4px 24px rgba(0,0,0,.3)}
.header-inner{max-width:820px;margin:0 auto;padding:14px 16px 10px}
.header-row1{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.header-brand{display:flex;flex-direction:column;gap:1px;min-width:0}
.header-brand h2{font-size:1.2rem;font-weight:700;color:#f1f5f9;letter-spacing:-.3px;white-space:nowrap}
.header-brand h2 .icon{color:#fbbf24;margin-right:6px}
.header-brand .subtitle{font-size:.7rem;color:#64748b;white-space:nowrap}
.header-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.header-email{font-size:.73rem;color:#94a3b8;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn-back{display:inline-flex;align-items:center;gap:4px;padding:6px 11px;border-radius:20px;font-size:.7rem;font-weight:500;color:#60a5fa;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);text-decoration:none;transition:all .2s;cursor:pointer;white-space:nowrap}
.btn-back:hover{background:rgba(96,165,250,.2)}
.btn-logout{display:inline-flex;align-items:center;gap:4px;padding:6px 11px;border-radius:20px;font-size:.7rem;font-weight:500;color:#f87171;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.2);text-decoration:none;transition:all .2s;cursor:pointer;white-space:nowrap}
.btn-logout:hover{background:rgba(248,113,113,.2);border-color:rgba(248,113,113,.35)}
.container{max-width:800px;margin:0 auto;padding:16px}
h1{font-size:1.3rem;margin:16px 0;color:#f1f5f9}
h2{font-size:1rem;color:#94a3b8;margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid #334155}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0}
.stat{background:#1e293b;border-radius:10px;padding:14px;text-align:center;border:1px solid #334155}
.stat .num{font-size:1.4rem;font-weight:700}
.stat .label{font-size:.68rem;color:#94a3b8;margin-top:2px}
.stat.green .num{color:#4ade80}
.stat.blue .num{color:#60a5fa}
.stat.yellow .num{color:#fbbf24}
table{width:100%;border-collapse:collapse;font-size:.78rem;margin-top:8px}
th{background:#1e293b;color:#94a3b8;font-weight:600;font-size:.7rem;text-transform:uppercase;padding:10px 8px;text-align:left;border-bottom:2px solid #334155}
td{padding:9px 8px;border-bottom:1px solid #1e293b;vertical-align:middle}
tr:hover td{background:rgba(96,165,250,.08)}
.badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:.65rem;font-weight:600}
.badge-admin{background:#78350f;color:#fbbf24}
.badge-user{background:#1e3a5f;color:#93c5fd}
.badge-active{background:#14532d;color:#4ade80}
.badge-inactive{background:#334155;color:#94a3b8}
.muted{color:#64748b;font-size:.7rem}
.visitor-chart{margin-top:8px}
.chart-bar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:.7rem}
.chart-bar .date{width:80px;color:#94a3b8;text-align:right}
.chart-bar .bar{height:16px;background:#2563eb;border-radius:4px;min-width:20px;transition:width .3s}
.chart-bar .count{color:#e2e8f0;font-weight:600;min-width:30px}
@media(max-width:500px){.stats-row{grid-template-columns:repeat(3,1fr)}.stat .num{font-size:1.1rem}table{font-size:.7rem}td,th{padding:6px 4px}.header-email{display:none}.header-brand h2{font-size:1.05rem}.header-inner{padding:12px 12px 10px}}
</style></head><body>

<div class="app-header">
  <div class="header-inner">
    <div class="header-row1">
      <div class="header-brand">
        <h2><span class="icon">&#9889;</span>Panel Admin</h2>
        <span class="subtitle">Halal Tracker</span>
      </div>
      <div class="header-right">
        <span class="header-email" title="{{ user_email }}">{{ user_email }}</span>
        <a href="/" class="btn-back">&#8592; Dashboard</a>
        <a href="/logout" class="btn-logout">&#10149; Keluar</a>
      </div>
    </div>
  </div>
</div>

<div class="container">

<h1>Panel Pentadbir</h1>

<div class="stats-row">
  <div class="stat blue"><div class="num">{{ total_users }}</div><div class="label">Jumlah Pengguna</div></div>
  <div class="stat green"><div class="num">{{ visits.today }}</div><div class="label">Visitor Hari Ini</div></div>
  <div class="stat yellow"><div class="num">{{ visits.week }}</div><div class="label">Visitor Minggu Ini</div></div>
</div>

<h2>Senarai Pengguna</h2>
<a href="/admin/certs" style="display:block;background:{% if pending_certs %}#78350f{% else %}#1e293b{% endif %};color:{% if pending_certs %}#fbbf24{% else %}#94a3b8{% endif %};border:1px solid #334155;border-radius:10px;padding:12px 14px;text-decoration:none;margin:8px 0 4px;font-size:.9rem">&#128220; Semakan Sijil Halal &mdash; <strong>{{ pending_certs }}</strong> menunggu semakan &rarr;</a>
<table><thead><tr><th>Email</th><th>Username</th><th>Login</th><th>Terakhir Login</th><th>Daftar</th><th>Status</th></tr></thead>
<tbody>
{% for u in users %}
<tr>
  <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{ u.email }}">{{ u.email }}</td>
  <td>{{ u.username }}</td>
  <td><strong>{{ u.login_count }}</strong>x</td>
  <td class="muted">{{ u.last_login or '-' }}</td>
  <td class="muted">{{ u.created_at[:10] }}</td>
  <td>{% if u.is_admin %}<span class="badge badge-admin">Admin</span>{% else %}<span class="badge badge-user">User</span>{% endif %}</td>
</tr>
{% endfor %}
</tbody></table>

<h2>Permintaan Mall Baharu</h2>
<table><thead><tr><th>Mall</th><th>Pautan</th><th>Dihantar oleh</th><th>Status</th><th>Tindakan</th></tr></thead>
<tbody>
{% for r in mall_reqs %}
<tr>
  <td>{{ r.mall_name }}</td>
  <td class="muted" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{% if r.mall_url %}<a href="{{ r.mall_url }}" target="_blank" rel="noopener" style="color:#60a5fa">{{ r.mall_url }}</a>{% else %}-{% endif %}</td>
  <td class="muted">{{ r.submitter_email or '-' }}</td>
  <td>{% if r.status=='pending' %}<span class="badge badge-inactive">Pending</span>{% elif r.status=='approved' %}<span class="badge badge-active">Approved</span>{% else %}<span class="badge badge-admin">Rejected</span>{% endif %}</td>
  <td>{% if r.status=='pending' %}<form method="POST" style="display:flex;gap:6px"><button formaction="/admin/mall/{{ r.id }}/approve" style="border:none;border-radius:6px;padding:5px 10px;font-weight:600;font-size:.72rem;cursor:pointer;background:#14532d;color:#4ade80">&#10003;</button><button formaction="/admin/mall/{{ r.id }}/reject" style="border:none;border-radius:6px;padding:5px 10px;font-weight:600;font-size:.72rem;cursor:pointer;background:#450a0a;color:#f87171">&times;</button></form>{% else %}<span class="muted">{{ (r.reviewed_at or '')[:10] }}</span>{% endif %}</td>
</tr>
{% endfor %}
{% if not mall_reqs %}<tr><td colspan="5" class="muted">- Tiada permintaan -</td></tr>{% endif %}
</tbody></table>

<h2>Visitor 30 Hari Terakhir</h2>
<div class="visitor-chart">
{% set max_cnt = visits_history[0].cnt if visits_history else 1 %}
{% for v in visits_history %}
<div class="chart-bar">
  <span class="date">{{ v.visit_date[5:] }}</span>
  <span class="bar" style="width:{{ (v.cnt / max_cnt * 100) if max_cnt > 0 else 0 }}%"></span>
  <span class="count">{{ v.cnt }}</span>
</div>
{% endfor %}
{% if not visits_history %}
<p class="muted">- Tiada data -</p>
{% endif %}
</div>

</div></body></html>'''

WHATSNEW_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Apa Baru — Halal Tracker</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.65}
.container{max-width:680px;margin:0 auto;padding:24px 16px 60px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:6px}
.back{color:#60a5fa;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);border-radius:20px;padding:7px 14px;font-size:.8rem;text-decoration:none;white-space:nowrap}
h1{font-size:1.7rem;color:#f1f5f9;margin-top:8px}
.lead{color:#94a3b8;font-size:.92rem;margin:6px 0 22px}
.card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:16px 18px;margin-bottom:12px;display:flex;gap:14px;align-items:flex-start}
.emoji{font-size:1.5rem;line-height:1.2;flex-shrink:0}
.card .t{font-weight:700;color:#f1f5f9;font-size:1rem}
.card .d{color:#94a3b8;font-size:.88rem;margin-top:2px}
.sec{font-size:.78rem;text-transform:uppercase;letter-spacing:.5px;color:#64748b;margin:22px 0 10px;font-weight:700}
.foot{color:#64748b;font-size:.8rem;margin-top:26px;text-align:center}
</style></head><body>
<div class="container">
  <div class="top">
    <div class="sec" style="margin:0">&#10024; Kemas kini terkini</div>
    <a href="/" class="back">&#8592; Kembali</a>
  </div>
  <h1>Apa Yang Baru?</h1>
  <div class="lead">Ciri-ciri terbaru untuk memudahkan anda menyemak status halal kedai di mall Malaysia.</div>

  {% for it in items %}
  <div class="card">
    <div class="emoji">{{ it[0] }}</div>
    <div><div class="t">{{ it[1] }}</div><div class="d">{{ it[2] }}</div></div>
  </div>
  {% endfor %}

  <div class="foot">Status halal dari portal rasmi JAKIM MyeHalal &bull; Tiada sijil bukan bermaksud haram.</div>
</div></body></html>'''

CERTS_HTML = '''<!DOCTYPE html><html lang="ms"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Semakan Sijil — Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.container{max-width:900px;margin:0 auto;padding:16px}
h1{font-size:1.3rem;margin:16px 0}
h2{font-size:1rem;color:#94a3b8;margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid #334155}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:10px}
.btn-back{color:#60a5fa;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);border-radius:20px;padding:6px 12px;font-size:.75rem;text-decoration:none}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:14px;margin-bottom:12px;display:flex;gap:14px;align-items:flex-start}
.card img{width:120px;height:120px;object-fit:cover;border-radius:8px;border:1px solid #334155;background:#0f172a;flex-shrink:0}
.card .meta{flex:1;min-width:0}
.card .o{font-weight:700}
.card .m{font-size:.8rem;color:#94a3b8}
.card .sub{font-size:.72rem;color:#64748b;margin-top:4px}
.acts{display:flex;gap:8px;margin-top:10px}
.acts button{border:none;border-radius:8px;padding:7px 14px;font-weight:600;font-size:.8rem;cursor:pointer}
.ap{background:#14532d;color:#4ade80}.rj{background:#450a0a;color:#f87171}
.muted{color:#64748b;font-size:.85rem}
.pill{display:inline-block;padding:2px 8px;border-radius:6px;font-size:.68rem;font-weight:600}
.pill.approved{background:#14532d;color:#4ade80}.pill.rejected{background:#450a0a;color:#f87171}
.note{font-size:.72rem;color:#93c5fd;margin-top:4px}
</style></head><body>
<div class="container">
<div class="topbar"><h1>&#128220; Semakan Sijil Halal</h1><a href="/admin" class="btn-back">&larr; Panel Admin</a></div>

<h2>Menunggu Semakan ({{ pending|length }})</h2>
{% for c in pending %}
<div class="card">
  <a href="/cert-image/{{ c.id }}" target="_blank"><img src="/cert-image/{{ c.id }}" alt="sijil"></a>
  <div class="meta">
    <div class="o">{{ c.outlet }}</div>
    <div class="m">{{ c.mall }}{% if c.lot %} &middot; {{ c.lot }}{% endif %}</div>
    <div class="sub">Dihantar oleh {{ c.submitter_email or '-' }} &middot; {{ c.created_at[:16] }}</div>
    <form method="POST" class="acts" onsubmit="this.querySelector('button.clicked').disabled=false">
      <button class="ap" formaction="/admin/cert/{{ c.id }}/approve">&#10003; Approve</button>
      <button class="rj" formaction="/admin/cert/{{ c.id }}/reject">&times; Reject</button>
    </form>
  </div>
</div>
{% endfor %}
{% if not pending %}<p class="muted">Tiada sijil menunggu semakan.</p>{% endif %}

<h2>Sejarah Semakan (50 terkini)</h2>
{% for c in done %}
<div class="card">
  <a href="/cert-image/{{ c.id }}" target="_blank"><img src="/cert-image/{{ c.id }}" alt="sijil"></a>
  <div class="meta">
    <div class="o">{{ c.outlet }} <span class="pill {{ c.status }}">{{ c.status }}</span></div>
    <div class="m">{{ c.mall }}{% if c.lot %} &middot; {{ c.lot }}{% endif %}</div>
    <div class="sub">Disemak oleh {{ c.reviewed_by or '-' }} &middot; {{ (c.reviewed_at or '')[:16] }}</div>
    {% if c.myehalal_note %}<div class="note">{{ c.myehalal_note }}</div>{% endif %}
  </div>
</div>
{% endfor %}
{% if not done %}<p class="muted">- Belum ada -</p>{% endif %}
</div></body></html>'''

# ── Routes ──────────────────────────────────────────────────────

# Global visitor tracking — runs on every request
@app.before_request
def auto_track_visitor():
    """Auto-track unique visitor on every page load."""
    # Skip static/bot requests
    if request.path.startswith('/static'):
        return
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')
    visitor_key = hashlib.sha256((ip + '|' + ua).encode()).hexdigest()[:32]
    today = datetime.utcnow().strftime('%Y-%m-%d')
    db = get_db()
    db.execute('INSERT OR IGNORE INTO visitors (visitor_key, visit_date) VALUES (?, ?)',
              (visitor_key, today))
    db.commit()
    db.close()

# Helper to get current visitor counts
def get_visitor_counts():
    today = datetime.utcnow().strftime('%Y-%m-%d')
    week_start = (datetime.utcnow() - timedelta(days=datetime.utcnow().weekday())).strftime('%Y-%m-%d')
    year_start = datetime.utcnow().strftime('%Y') + '-01-01'
    db = get_db()
    today_count = db.execute("SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date = ?", (today,)).fetchone()[0]
    week_count = db.execute("SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date >= ?", (week_start,)).fetchone()[0]
    year_count = db.execute("SELECT COUNT(DISTINCT visitor_key) FROM visitors WHERE visit_date >= ?", (year_start,)).fetchone()[0]
    db.close()
    return {'today': today_count, 'week': week_count, 'year': year_count}

@app.route('/')
def dashboard():
    auth = read_auth_cookie()
    logged_in = bool(auth)
    data = load_data()
    visits = get_visitor_counts()
    is_admin = False
    approved = []
    if logged_in:
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (auth[0],)).fetchone()
        db.close()
        is_admin = bool(user and user['is_admin'])
        approved = list(approved_certs_map().keys())
    else:
        # ponytail: guests get counts+summary only, no outlet rows — blur can't be bypassed via view-source
        data = {**data, 'malls': [{'mall': m['mall'], 'directory_url': m.get('directory_url'),
                                   'count': m['count'], 'summary': m['summary'], 'outlets': []}
                                  for m in data.get('malls', [])]}
    return render_template_string(DASHBOARD_HTML, data=data, user_email=(auth[1] if logged_in else ''),
                                  visits=visits, is_admin=is_admin, approved=approved, logged_in=logged_in,
                                  google_client_id=GOOGLE_CLIENT_ID,
                                  pending_certs=(pending_cert_count() if is_admin else 0))

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    auth = read_auth_cookie()
    db = get_db()
    users = db.execute('''
        SELECT id, email, username, login_count, last_login, created_at, is_admin
        FROM users ORDER BY last_login DESC
    ''').fetchall()
    total_users = len(users)
    # Also get visitor history for last 30 days
    visits_history = db.execute('''
        SELECT visit_date, COUNT(DISTINCT visitor_key) as cnt
        FROM visitors
        WHERE visit_date >= date('now', '-30 days')
        GROUP BY visit_date ORDER BY visit_date DESC
    ''').fetchall()
    mall_reqs = db.execute("SELECT * FROM mall_requests ORDER BY (status='pending') DESC, "
                           "COALESCE(reviewed_at, created_at) DESC LIMIT 60").fetchall()
    db.close()
    visits = get_visitor_counts()
    return render_template_string(ADMIN_HTML, users=users, total_users=total_users,
                                  visits=visits, visits_history=visits_history, mall_reqs=mall_reqs,
                                  user_email=auth[1], pending_certs=pending_cert_count())


@app.route('/submit-cert', methods=['POST'])
@login_required
def submit_cert():
    auth = read_auth_cookie()
    mall = (request.form.get('mall') or '').strip()[:120]
    outlet = (request.form.get('outlet') or '').strip()[:120]
    lot = (request.form.get('lot') or '').strip()[:120]
    f = request.files.get('image')
    if not mall or not outlet or not f or not f.filename:
        return jsonify(ok=False, error='Data tidak lengkap.'), 400
    if not _ext_ok(f.filename):
        return jsonify(ok=False, error='Format mesti JPG/PNG/WEBP.'), 400
    head = f.stream.read(16)
    f.stream.seek(0, 2); size = f.stream.tell(); f.stream.seek(0)
    if not any(head.startswith(s) for s in _SIGS):
        return jsonify(ok=False, error='Fail bukan imej sah.'), 400
    if size > MAX_UPLOAD:
        return jsonify(ok=False, error='Fail terlalu besar (max 6MB).'), 400
    fname = uuid.uuid4().hex + '.' + f.filename.rsplit('.', 1)[1].lower()
    f.save(os.path.join(UPLOAD_DIR, fname))
    db = get_db()
    db.execute("INSERT INTO cert_submissions (mall,outlet,lot,image_file,submitter_email,status) "
               "VALUES (?,?,?,?,?,'pending')", (mall, outlet, lot, fname, auth[1]))
    db.commit(); db.close()
    return jsonify(ok=True)


@app.route('/cert-image/<int:sid>')
@login_required
@admin_required
def cert_image(sid):
    db = get_db()
    row = db.execute("SELECT image_file FROM cert_submissions WHERE id=?", (sid,)).fetchone()
    db.close()
    if not row:
        abort(404)
    path = os.path.join(UPLOAD_DIR, os.path.basename(row['image_file']))
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.route('/admin/certs')
@login_required
@admin_required
def admin_certs():
    auth = read_auth_cookie()
    db = get_db()
    pending = db.execute("SELECT * FROM cert_submissions WHERE status='pending' ORDER BY created_at DESC").fetchall()
    done = db.execute("SELECT * FROM cert_submissions WHERE status!='pending' ORDER BY reviewed_at DESC LIMIT 50").fetchall()
    db.close()
    return render_template_string(CERTS_HTML, pending=pending, done=done,
                                  user_email=auth[1], visits=get_visitor_counts())


@app.route('/admin/cert/<int:sid>/<action>', methods=['POST'])
@login_required
@admin_required
def review_cert(sid, action):
    if action not in ('approve', 'reject'):
        abort(400)
    auth = read_auth_cookie()
    db = get_db()
    row = db.execute("SELECT * FROM cert_submissions WHERE id=?", (sid,)).fetchone()
    if not row:
        db.close(); abort(404)
    note = myehalal_lookup(row['outlet']) if action == 'approve' else None
    db.execute("UPDATE cert_submissions SET status=?, reviewed_at=CURRENT_TIMESTAMP, reviewed_by=?, "
               "myehalal_note=? WHERE id=?",
               ('approved' if action == 'approve' else 'rejected', auth[1], note, sid))
    db.commit(); db.close()
    return redirect(url_for('admin_certs'))

@app.route('/submit-mall', methods=['POST'])
@login_required
def submit_mall():
    auth = read_auth_cookie()
    name = (request.form.get('mall_name') or '').strip()[:160]
    url = (request.form.get('mall_url') or '').strip()[:300]
    if not name:
        return jsonify(ok=False, error='Sila isi nama mall.'), 400
    db = get_db()
    db.execute("INSERT INTO mall_requests (mall_name,mall_url,submitter_email,status) VALUES (?,?,?,'pending')",
               (name, url or None, auth[1]))
    db.commit(); db.close()
    return jsonify(ok=True)


@app.route('/admin/mall/<int:rid>/<action>', methods=['POST'])
@login_required
@admin_required
def review_mall(rid, action):
    if action not in ('approve', 'reject'):
        abort(400)
    auth = read_auth_cookie()
    db = get_db()
    db.execute("UPDATE mall_requests SET status=?, reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?",
               ('approved' if action == 'approve' else 'rejected', auth[1], rid))
    db.commit(); db.close()
    return redirect(url_for('admin_page'))


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            error = 'Sila isi email dan password.'
        else:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user and verify_password(password, user['password_hash']):
                db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE id = ?', (user['id'],))
                db.commit()
                db.close()
                resp = make_response(redirect(url_for('dashboard')))
                return set_auth_cookie(resp, user['id'], user['email'])
            else:
                error = 'Email atau password salah.'
            db.close()
    visits = get_visitor_counts()
    return render_template_string(LOGIN_HTML, error=error, visits=visits, google_client_id=GOOGLE_CLIENT_ID)


@app.route('/auth/google', methods=['POST'])
def auth_google():
    if not GOOGLE_CLIENT_ID:
        return jsonify(ok=False, error='Google sign-in belum dikonfigur.'), 400
    token = (request.get_json(silent=True) or {}).get('credential', '')
    if not token:
        return jsonify(ok=False, error='Tiada token.'), 400
    # Sahkan id_token via endpoint rasmi Google (tanpa dependency tambahan).
    # ponytail: tokeninfo call per login; tukar ke verifikasi JWT tempatan (google-auth) kalau volume tinggi.
    import urllib.request, urllib.parse
    try:
        with urllib.request.urlopen(
                'https://oauth2.googleapis.com/tokeninfo?id_token=' + urllib.parse.quote(token), timeout=15) as r:
            info = json.loads(r.read().decode())
    except Exception:
        return jsonify(ok=False, error='Token Google tidak sah.'), 401
    if info.get('aud') != GOOGLE_CLIENT_ID:
        return jsonify(ok=False, error='Token bukan untuk aplikasi ini.'), 401
    if info.get('iss') not in ('accounts.google.com', 'https://accounts.google.com'):
        return jsonify(ok=False, error='Pengeluar token tidak sah.'), 401
    if str(info.get('email_verified')).lower() != 'true' or not info.get('email'):
        return jsonify(ok=False, error='Email Google belum disahkan.'), 401
    email = info['email'].strip().lower()
    username = info.get('name') or email.split('@')[0]
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    admin = 1 if email in ADMIN_EMAILS else 0
    if user:
        # promote/demote existing account to match ADMIN_EMAILS on each login
        db.execute('UPDATE users SET last_login=CURRENT_TIMESTAMP, login_count=login_count+1, is_admin=? WHERE id=?',
                   (admin, user['id']))
        uid = user['id']
    else:
        # akaun baharu via Google — password_hash rawak (tak diguna)
        cur = db.execute('INSERT INTO users (email, username, password_hash, is_admin, last_login, login_count) '
                         'VALUES (?,?,?,?,CURRENT_TIMESTAMP,1)',
                         (email, username[:60], hash_password(secrets.token_hex(16)), admin))
        uid = cur.lastrowid
    db.commit(); db.close()
    resp = make_response(jsonify(ok=True))
    return set_auth_cookie(resp, uid, email)


@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not email or not password:
            error = 'Sila isi semua ruangan.'
        elif not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            error = 'Username: 3-30 aksara (huruf, nombor, _).'
        elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            error = 'Format email tidak sah.'
        elif len(password) < 8:
            error = 'Password mesti sekurang-kurangnya 8 aksara.'
        elif password != confirm:
            error = 'Password tidak sepadan.'
        else:
            db = get_db()
            existing = db.execute('SELECT id FROM users WHERE email = ? OR username = ?',
                                  (email, username)).fetchone()
            if existing:
                error = 'Email atau username telah digunakan.'
            else:
                pwd_hash = hash_password(password)
                db.execute('INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)',
                          (email, username, pwd_hash))
                db.commit()
                db.close()
                success = 'Pendaftaran berjaya! Sila <a href="/login" style="color:#60a5fa">login</a>.'
                return render_template_string(SIGNUP_HTML, error=None, success=success)
            db.close()
    return render_template_string(SIGNUP_HTML, error=error, success=success)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_page():
    error = None
    success = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            error = 'Sila masukkan email.'
        else:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user:
                token = generate_token()
                expires = datetime.utcnow() + timedelta(hours=1)
                db.execute('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                          (user['id'], token, expires))
                db.commit()
                reset_link = "/reset-password?token=" + token
                success = (
                    'Link reset telah dijana.<br><br>'
                    '<a href="' + reset_link + '" style="color:#60a5fa;font-weight:600">'
                    'Klik sini untuk reset password</a><br><br>'
                    '<small style="color:#64748b">(dalam production, link ini dihantar melalui email)</small>'
                )
            else:
                success = 'Jika email wujud, link reset telah dihantar.'
            db.close()
    return render_template_string(FORGOT_HTML, error=error, success=success)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_page():
    token = request.args.get('token', '')
    error = None
    success = None
    if not token:
        return redirect(url_for('forgot_page'))
    db = get_db()
    reset = db.execute(
        'SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expires_at > ?',
        (token, datetime.utcnow())
    ).fetchone()
    if not reset:
        db.close()
        return render_template_string(RESET_HTML, error='Token tidak sah atau telah tamat tempoh.',
                                      success=None, token=None)
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if len(password) < 8:
            error = 'Password mesti sekurang-kurangnya 8 aksara.'
        elif password != confirm:
            error = 'Password tidak sepadan.'
        else:
            pwd_hash = hash_password(password)
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pwd_hash, reset['user_id']))
            db.execute('UPDATE reset_tokens SET used = 1 WHERE id = ?', (reset['id'],))
            db.commit()
            db.close()
            success = 'Password berjaya ditukar! Sila <a href="/login" style="color:#60a5fa">login</a>.'
            return render_template_string(RESET_HTML, error=None, success=success, token=None)
    db.close()
    return render_template_string(RESET_HTML, error=error, success=success, token=token)

@app.route('/apa-baru')
def whats_new():
    # senarai plain-language utk pengguna biasa (bukan teknikal)
    items = [
        ("🔐", "Log masuk dengan Google", "Tak perlu ingat kata laluan — log masuk pantas guna akaun Google anda."),
        ("🔍", "Cari mall dengan mudah", "Taip nama mall pada kotak carian untuk terus jumpa, tak perlu skrol panjang."),
        ("🎯", "Tapis kedai ikut status", "Tekan kad Halal / Perlu Semak / Tiada Sijil / Non-Halal, atau guna dropdown, untuk lihat kedai ikut kategori."),
        ("📷", "Muat naik sijil halal", "Ada sijil halal sesebuah kedai? Muat naik gambar untuk bantu kami sahkan."),
        ("🏙️", "Cadang mall baharu", "Mall kegemaran anda tiada dalam senarai? Cadangkan dan kami akan tambah."),
        ("👀", "Lihat tanpa log masuk", "Boleh tengok ringkasan setiap mall dahulu; log masuk untuk senarai penuh."),
        ("🏬", "Banyak mall dalam satu tempat", "Semak kedai F&B untuk pelbagai pusat membeli-belah di seluruh Malaysia."),
        ("🔄", "Data sentiasa segar", "Senarai kedai dan status halal dikemas kini secara automatik setiap minggu."),
    ]
    return render_template_string(WHATSNEW_HTML, items=items)


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.set_cookie('auth', '', max_age=0)
    return resp

# ── Main ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8800, debug=False)
