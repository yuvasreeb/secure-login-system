"""
SecureAuth - Secure Login System (Flask + SQLite + bcrypt + optional 2FA)

Left side  : Register / Login / SQL-injection test / 2FA
Right side : Live server activity (validation, hashing, session, 2FA, DB, cookie)
"""
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

import bcrypt
import pyotp
from flask import Flask, abort, redirect, render_template_string, request, session, url_for

DEMO_MODE = True   # True = right panel shows the current 2FA code (for presentation only)
DB = "users.db"
LOG = []           # server activity shown on the right panel

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)


# ---------- helpers ----------
def log(msg, kind=""):
    LOG.insert(0, (datetime.now().strftime("%H:%M:%S"), msg, kind))
    del LOG[15:]


def query(sql, params=(), one=False, commit=False):
    """Always '?' placeholders -> SQL injection protection."""
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.execute(sql, params)
    result = cur.fetchone() if one else cur.fetchall()
    if commit:
        con.commit()
    con.close()
    return result


def init_db():
    query("""CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE NOT NULL,
               password_hash BLOB NOT NULL,
               totp_secret TEXT)""", commit=True)


def valid_username(u):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,20}", u))


def valid_password(p):
    return len(p) >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        token = session.get("csrf")
        if not token or request.form.get("csrf") != token:
            abort(400, "Invalid CSRF token")


def current_user():
    uid = session.get("user_id")
    return query("SELECT * FROM users WHERE id = ?", (uid,), one=True) if uid else None


def flag(name, value=True):
    f = session.get("flags", {})
    f[name] = value
    session["flags"] = f


# ---------- templates ----------
LAYOUT = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureAuth</title>
<style>
:root{--bg:#070b0b;--card:#0f1717;--bd:#1f2e2e;--tx:#e6fffb;--mu:#7fa3a0;--t:#14b8a6;--t2:#0d9488;
--er:#f87171;--erb:#2a1212;--wa:#fbbf24;--wab:#2a2008;--okb:#0b2a26;--code:#0a1212}
*{box-sizing:border-box}body{margin:0;padding:16px;background:var(--bg);color:var(--tx);
font:15px/1.5 "Segoe UI",Arial,sans-serif}
h1{font-size:21px;margin:0 0 14px}h1 span{color:var(--t)}h2{font-size:18px;margin:0 0 12px}
h3{font-size:12px;margin:0 0 10px;color:var(--t);text-transform:uppercase;letter-spacing:.08em}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.3fr);gap:16px}
@media(max-width:780px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:20px;margin-bottom:16px}
label{font-size:13px;color:var(--mu)}
input[type=text],input[type=password]{width:100%;padding:10px;margin:5px 0 14px;border:1px solid var(--bd);
border-radius:8px;font-size:15px;background:var(--code);color:var(--tx)}
input:focus{outline:2px solid var(--t2)}
button{padding:10px 14px;background:var(--t);color:#042f2a;font-weight:600;border:0;border-radius:8px;
font-size:14px;cursor:pointer;width:100%}button:hover{background:#2dd4bf}
button.alt{background:transparent;color:var(--t);border:1px solid var(--t2)}
button.red{background:var(--erb);color:var(--er);border:1px solid #5b2020;margin-top:10px}
.msg{padding:9px 11px;border-radius:8px;margin-bottom:12px;font-size:14px}
.err{background:var(--erb);color:var(--er)}.ok{background:var(--okb);color:var(--t)}
a{color:var(--t)}.c{text-align:center;font-size:14px;margin-top:12px}
code,.mono{font-family:Consolas,monospace;font-size:12.5px;background:var(--code);padding:2px 6px;
border-radius:5px;word-break:break-all}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
.chips{display:grid;grid-template-columns:1fr;gap:8px}
.chip{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;border:1px solid var(--bd);font-size:13px;color:var(--mu)}
.chip.on{background:var(--okb);border-color:var(--t2);color:var(--t);font-weight:600}
.log div{padding:6px 9px;border-radius:7px;margin-bottom:6px;font-size:13px;word-break:break-word;background:var(--code)}
.log .good{background:var(--okb);color:var(--t)}.log .bad{background:var(--erb);color:var(--er)}
.log .warn{background:var(--wab);color:var(--wa)}
.auth{text-align:center;font-size:30px;letter-spacing:.2em;font-family:Consolas,monospace;font-weight:700;color:var(--t)}
.muted{color:var(--mu);font-size:13px}
.spin{display:inline-block;width:14px;height:14px;border:3px dashed #042f2a;border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes sp{to{transform:rotate(360deg)}}
</style></head><body>
<h1>🔐 Secure<span>Auth</span></h1>
<div class="grid">
  <div><div class="card">{{ left|safe }}</div></div>
  <div>
    <div class="card"><h3>Security status</h3><div class="chips">
      {% for name, on in chips %}<div class="chip{{ ' on' if on }}"><span>{{ name }}</span><span>{{ '✔ Done' if on else 'Pending' }}</span></div>{% endfor %}
    </div></div>
    {% if demo_code %}<div class="card"><h3>📱 Authenticator app (demo mode)</h3>
      <div class="auth">{{ demo_code }}</div>
      <div class="c muted">In real use, get this code from Google Authenticator</div></div>{% endif %}
    <div class="card"><h3>🧾 Live server activity</h3><div class="log">
      {% for t, m, k in logs %}<div class="{{ k }}"><span class="muted">{{ t }}</span> {{ m }}</div>
      {% else %}<span class="muted">No activity yet.</span>{% endfor %}
    </div></div>
    <div class="card"><h3>🗄️ Database – users table</h3><div class="scroll">
      {% if users %}<table><tr><th>id</th><th>username</th><th>password_hash</th><th>2FA</th></tr>
      {% for u in users %}<tr><td>{{ u.id }}</td><td>{{ u.username }}</td>
      <td><span class="mono">{{ u.hash }}</span></td><td>{{ 'on' if u.tf else 'off' }}</td></tr>{% endfor %}</table>
      {% else %}<span class="muted">Empty – register a user first.</span>{% endif %}
    </div></div>
    <div class="card"><h3>🍪 Session cookie</h3>
      {% if sid %}<span class="mono">session={{ sid }}; HttpOnly; SameSite=Lax; Max-Age=900</span>
      <div class="muted" style="margin-top:6px">Expires automatically after 15 minutes.</div>
      {% else %}<span class="muted">No session (not logged in).</span>{% endif %}
    </div>
  </div>
</div>
<script>
// Show a spinner on buttons marked data-load, then submit the form
document.querySelectorAll("form").forEach(f=>f.addEventListener("submit",e=>{
  const b=f.querySelector("[data-load]");
  if(!b||f.dataset.sent) return;
  e.preventDefault(); f.dataset.sent=1;
  b.innerHTML='<span class="spin"></span>'+b.dataset.load; b.style.pointerEvents="none";
  setTimeout(()=>f.submit(),900);
}));
</script>
</body></html>
"""


def page(body, **ctx):
    left = render_template_string(body, csrf=csrf_token(), **ctx)  # autoescaped -> XSS safe
    rows = query("SELECT id, username, password_hash, totp_secret FROM users")
    users = [{"id": r["id"], "username": r["username"], "hash": bytes(r["password_hash"]).decode(),
              "tf": bool(r["totp_secret"])} for r in rows]
    secret = None                      # secret used only for the demo code panel
    if DEMO_MODE:
        if session.get("pending_2fa"):
            u = query("SELECT totp_secret FROM users WHERE id = ?", (session["pending_2fa"],), one=True)
            secret = u["totp_secret"] if u else None
        elif request.endpoint == "enable_2fa":
            secret = session.get("new_secret")
    flags = session.get("flags", {})
    chips = [("Input validated", flags.get("val")), ("Password hashed", flags.get("hash")),
             ("SQL injection blocked", flags.get("sqli")), ("2FA verified", flags.get("tf")),
             ("Session active", "user_id" in session)]
    return render_template_string(
        LAYOUT, left=left, chips=chips, logs=LOG, users=users, sid=session.get("sid"),
        demo_code=pyotp.TOTP(secret).now() if secret else None)


# ---------- routes ----------
@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


REGISTER = """
<h2>Create account</h2>
{% if error %}<div class="msg err">{{ error }}</div>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
  <label>Username (3-20 letters, numbers, _)</label><input type="text" name="username" required>
  <label>Password (min 8, letter + number)</label><input type="password" name="password" required>
  <button>Register</button></form>
<div class="c">Already have an account? <a href="{{ url_for('login') }}">Login</a></div>
"""


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not valid_username(username):
            error = "Username must be 3-20 characters: letters, numbers or underscore."
            log("Registration blocked: invalid username", "bad")
        elif not valid_password(password):
            error = "Password needs 8+ characters with a letter and a number."
            log("Registration blocked: weak password", "bad")
        elif query("SELECT id FROM users WHERE username = ?", (username,), one=True):
            error = "Username already taken."
        else:
            log("Input validation passed", "good")
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            query("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed), commit=True)
            log("Password hashed with bcrypt + salt. Real password NOT stored", "good")
            log("SQL: INSERT INTO users VALUES (?, ?)  <- parameterized", "")
            flag("val"); flag("hash")
            return redirect(url_for("login", registered=1))
    return page(REGISTER, error=error)


LOGIN = """
<h2>Login</h2>
{% if registered %}<div class="msg ok">Registration successful. Please login.</div>{% endif %}
{% if error %}<div class="msg err">{{ error }}</div>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
  <label>Username</label><input type="text" name="username" required>
  <label>Password</label><input type="password" name="password" required>
  <button data-load="Logging in...">Login</button></form>
<form method="post" action="{{ url_for('attack') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  <button class="red">💉 Try SQL injection attack</button></form>
<div class="c"><a href="{{ url_for('register') }}">Create account</a></div>
"""


def finish_login(user):
    flags = session.get("flags", {})
    session.clear()                      # new session -> prevents session fixation
    session["flags"] = flags
    session["user_id"] = user["id"]
    session["sid"] = secrets.token_hex(16)
    session.permanent = True
    log('User "%s" logged in. New session created' % user["username"], "good")
    return redirect(url_for("dashboard"))


def try_login(username, password, attack=False):
    """Shared by normal login and the attack demo. Returns (redirect_or_None, error)."""
    if attack:
        log("ATTACK -> username = " + username, "warn")
        log("Unprotected app would run: WHERE username='' OR '1'='1' -> always TRUE -> attacker logs in!", "warn")
    if not valid_username(username):
        log("Validation FAILED - input rejected before database", "good")
        if attack:
            flag("sqli")
            log("SQL injection BLOCKED", "good")
        return None, "Invalid username or password."
    flag("val")
    log('SQL: SELECT * FROM users WHERE username = ?  <- ["%s"]' % username, "")
    user = query("SELECT * FROM users WHERE username = ?", (username,), one=True)
    if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
        log("bcrypt compare: password matches", "good")
        if user["totp_secret"]:
            flags = session.get("flags", {})
            session.clear()
            session["flags"] = flags
            session["pending_2fa"] = user["id"]
            log("2FA required - waiting for 6-digit code", "")
            return redirect(url_for("verify_2fa")), None
        return finish_login(user), None
    log("Login failed - generic error shown", "bad")
    return None, "Invalid username or password."


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        resp, error = try_login(request.form.get("username", "").strip(), request.form.get("password", ""))
        if resp:
            return resp
    return page(LOGIN, error=error, registered=request.args.get("registered"))


@app.route("/attack", methods=["POST"])
def attack():
    try_login("' OR '1'='1", "anything", attack=True)
    return page(LOGIN, error="Attack blocked. Invalid username or password.")


VERIFY = """
<h2>Two-Factor Authentication</h2>
{% if error %}<div class="msg err">{{ error }}</div>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
  <label>Enter the 6-digit code from your Authenticator app</label>
  <input type="text" name="code" maxlength="6" required><button data-load="Verifying...">Verify</button></form>
"""


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa")
    if not uid:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        user = query("SELECT * FROM users WHERE id = ?", (uid,), one=True)
        if pyotp.TOTP(user["totp_secret"]).verify(request.form.get("code", "").strip()):
            log("2FA code correct", "good")
            flag("tf")
            return finish_login(user)
        error = "Wrong code. Try again."
        log("2FA code wrong", "bad")
    return page(VERIFY, error=error)


DASH = """
<h2>Welcome, {{ user.username }} 🎉</h2>
<div class="msg ok">You are logged in securely.</div>
<p>Two-Factor Authentication: <b>{{ 'ENABLED' if user.totp_secret else 'Not enabled' }}</b></p>
{% if not user.totp_secret %}
  <a href="{{ url_for('enable_2fa') }}"><button type="button" class="alt">Enable 2FA</button></a><div style="height:10px"></div>
{% endif %}
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  <button class="alt">Logout</button></form>
"""


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return page(DASH, user=user)


ENABLE = """
<h2>Enable 2FA</h2>
{% if error %}<div class="msg err">{{ error }}</div>{% endif %}
<p class="muted">Google Authenticator &rarr; Add account &rarr; Enter a setup key, then paste:</p>
<p><code>{{ secret }}</code></p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
  <label>Enter the 6-digit code shown in the app</label>
  <input type="text" name="code" maxlength="6" required><button>Confirm &amp; Enable</button></form>
<a href="{{ url_for('dashboard') }}"><button type="button" class="alt" style="margin-top:10px">&larr; Back</button></a>
"""


@app.route("/enable-2fa", methods=["GET", "POST"])
def enable_2fa():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if "new_secret" not in session:
        session["new_secret"] = pyotp.random_base32()
    secret = session["new_secret"]
    error = None
    if request.method == "POST":
        if pyotp.TOTP(secret).verify(request.form.get("code", "").strip()):
            query("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]), commit=True)
            session.pop("new_secret", None)
            flag("tf")
            log("2FA enabled for " + user["username"], "good")
            return redirect(url_for("dashboard"))
        error = "Wrong code. Try again."
    return page(ENABLE, secret=secret, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    log("Session destroyed. Logged out", "good")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
