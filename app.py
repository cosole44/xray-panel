#!/usr/bin/env python3
"""
Xray Panel — Лёгкая панель управления пользователями Xray для 3x-ui
https://github.com/cosole44/xray-panel
"""

import os, sys, json, secrets, time, uuid, hashlib, subprocess, re
from datetime import datetime
from functools import wraps
from urllib.parse import quote

import requests
from flask import Flask, render_template_string, request, redirect, url_for, session, abort

# ============================================================
# Auto-detect 3x-ui configuration
# ============================================================
def detect_xui():
    config = {"base_url": "https://127.0.0.1:2053", "token": "", "domain": "", "port": 2053}

    for p in ["/usr/local/x-ui/x-ui", "/usr/bin/x-ui"]:
        if os.path.exists(p):
            try:
                out = subprocess.run([p, "setting", "-show"], capture_output=True, text=True, timeout=5).stdout
                for line in out.split("\n"):
                    if "port:" in line:
                        config["port"] = int(line.split(":")[-1].strip())
                        config["base_url"] = f"https://127.0.0.1:{config['port']}"
                    if "webBasePath:" in line:
                        bp = line.split(":")[-1].strip()
                        if bp and bp != "/":
                            config["base_url"] += bp
                tok = subprocess.run([p, "setting", "-getApiToken"], capture_output=True, text=True, timeout=5).stdout
                for line in tok.split("\n"):
                    if "apiToken:" in line:
                        config["token"] = line.split(":", 1)[1].strip()
            except Exception:
                pass
            break

    for d in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.path.isfile(fp):
                    try:
                        m = re.search(r"server_name\s+([^;\s]+)", open(fp).read())
                        if m and "." in m.group(1):
                            config["domain"] = m.group(1)
                    except Exception:
                        pass

    for d in sorted(os.listdir("/root/cert")) if os.path.isdir("/root/cert") else []:
        cp = os.path.join("/root/cert", d, "fullchain.pem")
        kp = os.path.join("/root/cert", d, "privkey.pem")
        if os.path.exists(cp) and os.path.exists(kp):
            config["cert"], config["key"] = cp, kp
            if not config["domain"]:
                config["domain"] = d
            break

    return config


# ============================================================
# Configuration from environment
# ============================================================
XUI = detect_xui()
XUI_HDR = {"Authorization": f"Bearer {XUI['token']}"} if XUI["token"] else {}

PANEL_USER = os.environ.get("XPANEL_USER", "admin")
PANEL_PASS_HASH = hashlib.sha256(os.environ.get("XPANEL_PASS", "admin123").encode()).hexdigest()
FLASK_PORT = int(os.environ.get("XPANEL_PORT", "8889"))
PANEL_DOMAIN = os.environ.get("XPANEL_DOMAIN", "")
SECRET_PATH = os.environ.get("XPANEL_SECRET", "")

# 3x-ui connection (from environment or auto-detect)
XUI_BASE = os.environ.get("XUI_BASE_URL", "")
XUI_TOKEN = os.environ.get("XUI_API_TOKEN", "")

if not XUI_BASE:
    XUI = detect_xui()
    XUI_BASE = XUI["base_url"]
    XUI_TOKEN = XUI["token"]
    if not PANEL_DOMAIN:
        PANEL_DOMAIN = XUI.get("domain", "")
elif not XUI_TOKEN:
    XUI = detect_xui()
    XUI_TOKEN = XUI.get("token", "")

XUI_HDR = {"Authorization": f"Bearer {XUI_TOKEN}"} if XUI_TOKEN else {}

app = Flask(__name__)
app.secret_key = os.environ.get("XPANEL_SECRET_KEY", secrets.token_hex(32))

# Base URL prefix for redirects (nginx strips the secret path)
BASEPATH = f"/{SECRET_PATH}" if SECRET_PATH else ""


# ============================================================
# Helpers
# ============================================================
def redir(endpoint, **kwargs):
    """Redirect with secret path prefix."""
    return redirect(f"{BASEPATH}/{endpoint}" + ("?" + "&".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""))


def login_required(f):
    @wraps(f)
    def d(*args, **kwargs):
        if not session.get("auth"):
            return redir("login")
        return f(*args, **kwargs)
    return d


def xui_api(method, path, data=None):
    try:
        # Remove double slashes and strip trailing slash from base
        base = XUI_BASE.rstrip('/')
        while '//' in base.replace('https://', '').replace('http://', ''):
            base = base.replace('//', '/')
        url = f"{base}{path}"
        if method == "GET":
            r = requests.get(url, headers=XUI_HDR, verify=False, timeout=15)
        else:
            r = requests.post(url, headers={**XUI_HDR, "Content-Type": "application/x-www-form-urlencoded"},
                              data=data, verify=False, timeout=15)
        return r.json()
    except Exception as e:
        return {"success": False, "msg": str(e), "obj": None}


def fmt_bytes(b):
    if b == 0:
        return "0 B"
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"


def get_full_inbound(inb_id):
    resp = xui_api("GET", f"/panel/api/inbounds/get/{inb_id}")
    return resp["obj"] if resp.get("success") else None


def update_full_inbound(inb):
    settings = inb.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    stream = inb.get("streamSettings", {})
    if isinstance(stream, str):
        stream = json.loads(stream)
    sniffing = inb.get("sniffing", {})
    if isinstance(sniffing, str):
        sniffing = json.loads(sniffing)
    data = {
        "remark": inb.get("remark", ""),
        "enable": str(inb.get("enable", True)).lower(),
        "port": inb.get("port", 443),
        "protocol": inb.get("protocol", "vless"),
        "settings": json.dumps(settings),
        "streamSettings": json.dumps(stream),
        "sniffing": json.dumps(sniffing),
    }
    return xui_api("POST", f"/panel/api/inbounds/update/{inb['id']}", data)


def build_link(client_uuid, client_email, inb):
    proto = inb.get("protocol", "vless")
    port = inb.get("port", 443)
    stream = inb.get("streamSettings", {})
    if isinstance(stream, str):
        stream = json.loads(stream)
    if proto == "vless":
        reality = stream.get("realitySettings", {})
        pubkey = reality.get("settings", {}).get("publicKey", "")
        snis = reality.get("serverNames", ["dl.google.com"])
        sni = snis[0] if snis else "dl.google.com"
        xhttp = stream.get("xhttpSettings", {})
        path = xhttp.get("path", "/")
        params = f"type=xhttp&security=reality&pbk={pubkey}&fp=chrome&sni={sni}&s={quote(path)}&xPaddingBytes=100-1000"
        return f"vless://{client_uuid}@{PANEL_DOMAIN}:{port}?{params}#{quote('Xray-' + client_email)}"
    elif proto == "hysteria":
        clients = inb.get("settings", {}).get("clients", [])
        auth = clients[0].get("auth", "") if clients else ""
        sni = stream.get("tlsSettings", {}).get("serverName", "")
        return f"hysteria2://{auth}@{PANEL_DOMAIN}:{port}?insecure=1&sni={sni}#{quote('Xray-' + client_email)}"
    return ""


def build_sub_url(sub_id):
    sub_port = XUI["port"]
    return f"https://{PANEL_DOMAIN}:{sub_port}/sub/{sub_id}"


# ============================================================
# HTML Templates
# ============================================================
LOGIN_PAGE = '''<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Xray Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 100%);color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.box{background:rgba(30,41,59,0.95);backdrop-filter:blur(20px);border:1px solid rgba(148,163,184,0.15);border-radius:20px;padding:32px 28px;width:100%;max-width:380px;box-shadow:0 25px 50px rgba(0,0,0,0.5)}
.logo{text-align:center;font-size:56px;margin-bottom:8px;filter:drop-shadow(0 0 20px rgba(59,130,246,0.4))}
h1{text-align:center;font-size:22px;font-weight:700;margin-bottom:4px;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{text-align:center;color:#94a3b8;font-size:13px;margin-bottom:28px}
label{display:block;margin-bottom:6px;font-size:12px;color:#94a3b8;font-weight:500}
input{width:100%;padding:14px 16px;background:rgba(15,23,42,0.8);border:1.5px solid rgba(148,163,184,0.2);border-radius:12px;color:#e2e8f0;font-size:15px;outline:none;margin-bottom:14px;transition:border-color .2s}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;margin-top:4px}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 25px rgba(59,130,246,0.35)}
.btn:active{transform:translateY(0)}
.err{background:rgba(239,68,68,0.12);color:#f87171;border:1px solid rgba(239,68,68,0.25);padding:12px;border-radius:10px;margin-bottom:16px;font-size:13px;text-align:center}
</style></head><body>
<div class="box">
<div class="logo">&#9889;</div>
<h1>Xray Panel</h1>
<p class="sub">User Management</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST"><label>Username</label><input type="text" name="username" required autofocus>
<label>Password</label><input type="password" name="password" required>
<button type="submit" class="btn">Sign In</button></form></div></body></html>'''

DASHBOARD_PAGE = '''<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Xray Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f172a;--card:#1e293b;--border:rgba(148,163,184,0.12);--text:#e2e8f0;--muted:#94a3b8;--accent:#3b82f6;--accent2:#8b5cf6;--green:#22c55e;--red:#ef4444;--orange:#f59e0b;--radius:16px}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:rgba(30,41,59,0.95);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:14px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:17px;font-weight:700;display:flex;align-items:center;gap:8px}
.header h1 span{font-size:22px}
.hdr-right{display:flex;gap:6px;align-items:center}
.container{max-width:900px;margin:0 auto;padding:16px;padding-bottom:100px}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;right:0;width:60px;height:60px;border-radius:50%;filter:blur(30px);opacity:0.15}
.stat:nth-child(1)::before{background:var(--accent)}.stat:nth-child(2)::before{background:var(--green)}
.stat:nth-child(3)::before{background:var(--red)}.stat:nth-child(4)::before{background:var(--accent2)}
.stat .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.stat .value{font-size:24px;font-weight:800}
.stat .value.g{color:var(--green)}.stat .value.b{color:var(--accent)}.stat .value.p{color:var(--accent2)}.stat .value.r{color:var(--red)}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}
.card-h{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.card-h h2{font-size:14px;font-weight:600}
.user-card{padding:14px 16px;border-bottom:1px solid var(--border);transition:background .15s}
.user-card:last-child{border-bottom:none}
.user-card:hover{background:rgba(59,130,246,0.03)}
.user-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.user-name{font-size:15px;font-weight:600;display:flex;align-items:center;gap:8px}
.user-meta{display:flex;gap:12px;font-size:12px;color:var(--muted);flex-wrap:wrap}
.user-meta span{display:flex;align-items:center;gap:4px}
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge.g{background:rgba(34,197,94,0.12);color:var(--green)}.badge.r{background:rgba(239,68,68,0.12);color:var(--red)}
.badge.o{background:rgba(245,158,11,0.12);color:var(--orange)}
.user-actions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:10px 16px;border-radius:10px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:all .15s;min-height:40px}
.btn:active{transform:scale(0.97)}
.btn-p{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff}
.btn-p:hover{box-shadow:0 4px 15px rgba(59,130,246,0.4)}
.btn-s{background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff}
.btn-s:hover{box-shadow:0 4px 15px rgba(34,197,94,0.4)}
.btn-d{background:rgba(239,68,68,0.12);color:var(--red);border:1px solid rgba(239,68,68,0.2)}
.btn-d:hover{background:rgba(239,68,68,0.2)}
.btn-g{background:rgba(148,163,184,0.1);color:var(--muted);border:1px solid var(--border)}
.btn-g:hover{background:rgba(148,163,184,0.15);color:var(--text)}
.btn-full{width:100%}
.btn-xl{padding:16px 20px;font-size:15px;min-height:52px;border-radius:14px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);z-index:200;align-items:flex-end;justify-content:center;padding:0}
.modal-bg.on{display:flex}
@media(min-width:600px){.modal-bg{align-items:center;padding:16px}}
.modal{background:var(--card);border:1px solid var(--border);border-radius:20px 20px 0 0;padding:24px 20px;width:100%;max-width:500px;max-height:90vh;overflow-y:auto;animation:slideUp .25s ease}
@media(min-width:600px){.modal{border-radius:20px}}
@keyframes slideUp{from{transform:translateY(30px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal h3{font-size:18px;font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:8px}
.modal-handle{width:40px;height:4px;background:rgba(148,163,184,0.3);border-radius:2px;margin:0 auto 16px;display:block}
.fg{margin-bottom:16px}
.fg label{display:block;margin-bottom:6px;font-size:12px;color:var(--muted);font-weight:500}
.fg input,.fg select{width:100%;padding:13px 14px;background:rgba(15,23,42,0.8);border:1.5px solid var(--border);border-radius:12px;color:var(--text);font-size:14px;outline:none;transition:border-color .2s;-webkit-appearance:none}
.fg input:focus,.fg select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.fg select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8'%3E%3Cpath d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
.fa{display:flex;gap:10px;margin-top:20px}
.fa .btn{flex:1}
.sub-url{background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-family:'SF Mono',Monaco,monospace;font-size:11px;word-break:break-all;cursor:pointer;transition:border-color .2s;line-height:1.5}
.sub-url:active{border-color:var(--accent);background:rgba(59,130,246,0.05)}
.flash{padding:12px 16px;border-radius:12px;margin-bottom:16px;font-size:13px;font-weight:500}
.flash.ok{background:rgba(34,197,94,0.1);color:var(--green);border:1px solid rgba(34,197,94,0.2)}
.flash.er{background:rgba(239,68,68,0.1);color:var(--red);border:1px solid rgba(239,68,68,0.2)}
.empty{text-align:center;padding:40px 20px;color:var(--muted);font-size:14px}
.empty-icon{font-size:40px;margin-bottom:8px;opacity:0.5}
.quick-actions{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px}
.qa-btn{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center;cursor:pointer;transition:all .2s}
.qa-btn:hover{border-color:var(--accent);background:rgba(59,130,246,0.05)}
.qa-btn .icon{font-size:28px;margin-bottom:6px}
.qa-btn .txt{font-size:13px;font-weight:500;color:var(--muted)}
</style></head><body>
<div class="header">
<h1><span>&#9889;</span> Xray</h1>
<div class="hdr-right">
<a href="/logout" class="btn btn-g" style="font-size:12px;padding:8px 12px">Exit</a>
</div></div>
<div class="container">
{% if flash_msg %}<div class="flash {{ flash_type }}">{{ flash_msg }}</div>{% endif %}
<div class="stats">
<div class="stat"><div class="label">Users</div><div class="value b">{{ users|length }}</div></div>
<div class="stat"><div class="label">Active</div><div class="value g">{{ active }}</div></div>
<div class="stat"><div class="label">Expired</div><div class="value r">{{ expired }}</div></div>
<div class="stat"><div class="label">Traffic</div><div class="value p">{{ total_tr }}</div></div>
</div>
<div class="quick-actions">
<div class="qa-btn" onclick="showModal('m-add')"><div class="icon">+</div><div class="txt">Add User</div></div>
<div class="qa-btn" onclick="location.reload()"><div class="icon">&#8635;</div><div class="txt">Refresh</div></div>
</div>
<div class="card">
<div class="card-h"><h2>Users ({{ users|length }})</h2></div>
{% for u in users %}
<div class="user-card">
<div class="user-top"><div class="user-name">{{ u.email }}
{% if not u.enable %}<span class="badge r">Off</span>{% elif u.expired %}<span class="badge o">Expired</span>{% else %}<span class="badge g">Active</span>{% endif %}</div></div>
<div class="user-meta"><span>&#128190; {{ u.traffic }}</span><span>&#128197; {{ u.expiry_str }}</span><span>&#128225; {{ u.proto }}</span></div>
<div class="user-actions">
<button class="btn btn-p" style="flex:1" onclick="showLinks('{{ u.email }}','{{ u.vless_url|e }}','{{ u.sub_url|e }}')">&#128279; Links</button>
<button class="btn btn-s" style="flex:1" onclick="showExtend('{{ u.email }}','{{ u.inbound_id }}','{{ u.uuid }}')">&#128197; Extend</button>
<button class="btn btn-d" onclick="delUser('{{ u.email }}','{{ u.inbound_id }}')">&#128465;</button>
</div></div>
{% endfor %}
{% if not users %}<div class="empty"><div class="empty-icon">&#128100;</div>No users</div>{% endif %}
</div></div>

<div class="modal-bg" id="m-add" onclick="if(event.target===this)hideModal('m-add')">
<div class="modal"><span class="modal-handle"></span><h3>&#10133; New User</h3>
<form method="POST" action="/add">
<div class="fg"><label>Name</label><input type="text" name="email" required placeholder="e.g. john"></div>
<div class="fg"><label>Expiry (days)</label><input type="number" name="expiry_days" value="30" min="1"></div>
<div class="fg"><label>Traffic Limit (GB, 0=unlimited)</label><input type="number" name="total_gb" value="0" min="0"></div>
<div class="fg"><label>Inbound</label><select name="inbound_id">{% for i in inbounds %}<option value="{{ i.id }}">{{ i.remark }}</option>{% endfor %}</select></div>
<div class="fa"><button type="button" class="btn btn-g" onclick="hideModal('m-add')">Cancel</button><button type="submit" class="btn btn-s btn-xl">Create</button></div>
</form></div></div>

<div class="modal-bg" id="m-ext" onclick="if(event.target===this)hideModal('m-ext')">
<div class="modal"><span class="modal-handle"></span><h3>&#128197; Extend</h3>
<form method="POST" action="/extend">
<input type="hidden" name="email" id="ext-email"><input type="hidden" name="inbound_id" id="ext-inbound"><input type="hidden" name="client_uuid" id="ext-uuid">
<div class="fg"><label>Days to add</label><input type="number" name="days" value="30" min="1"></div>
<div class="fa"><button type="button" class="btn btn-g" onclick="hideModal('m-ext')">Cancel</button><button type="submit" class="btn btn-s btn-xl">Extend</button></div>
</form></div></div>

<div class="modal-bg" id="m-links" onclick="if(event.target===this)hideModal('m-links')">
<div class="modal"><span class="modal-handle"></span><h3>&#128279; Links</h3>
<p style="color:var(--muted);font-size:13px;margin-bottom:12px" id="links-user"></p>
<div class="fg"><label>VLESS Link</label><div class="sub-url" id="link-vless" onclick="copyEl(this)"></div></div>
<div class="fg"><label>Subscription URL</label><div class="sub-url" id="link-sub" onclick="copyEl(this)"></div></div>
<div class="fa"><button type="button" class="btn btn-g btn-full" onclick="hideModal('m-links')">Close</button></div>
</div></div>

<form method="POST" action="/delete" id="del-form" style="display:none"><input type="hidden" name="email" id="del-email"><input type="hidden" name="inbound_id" id="del-inbound"></form>

<script>
function showModal(id){document.getElementById(id).classList.add('on')}
function hideModal(id){document.getElementById(id).classList.remove('on')}
function showExtend(e,i,u){document.getElementById('ext-email').value=e;document.getElementById('ext-inbound').value=i;document.getElementById('ext-uuid').value=u;showModal('m-ext')}
function showLinks(e,v,s){document.getElementById('links-user').textContent=e;document.getElementById('link-vless').textContent=v;document.getElementById('link-sub').textContent=s;showModal('m-links')}
function delUser(e,i){if(confirm('Delete '+e+'?')){document.getElementById('del-email').value=e;document.getElementById('del-inbound').value=i;document.getElementById('del-form').submit()}}
function copyEl(el){navigator.clipboard.writeText(el.textContent).then(()=>{var t=document.createElement('div');t.textContent='Copied!';t.style.cssText='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#22c55e;color:#fff;padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;z-index:9999;animation:fadeIn .3s';document.body.appendChild(t);setTimeout(()=>t.remove(),1500)})}
</script></body></html>'''


# ============================================================
# Routes
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if (request.form.get("username") == PANEL_USER and
                hashlib.sha256(request.form.get("password", "").encode()).hexdigest() == PANEL_PASS_HASH):
            session["auth"] = True
            return redir("")
        error = "Wrong credentials"
    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redir("login")


@app.route("/")
@login_required
def dashboard():
    resp = xui_api("GET", "/panel/api/inbounds/list")
    inbounds = resp.get("obj", []) if resp.get("success") else []

    users, active, expired, total_bytes = [], 0, 0, 0
    now_ms = int(time.time() * 1000)

    for inb in inbounds:
        settings = inb.get("settings", {})
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        for c in settings.get("clients", []):
            email = c.get("email", "")
            cid = c.get("id", "")
            exp = c.get("expiryTime", 0)
            en = c.get("enable", True)
            sub_id = c.get("subId", email)
            stats = next((s for s in inb.get("clientStats", []) if s.get("email") == email), None)
            used = (stats.get("up", 0) if stats else 0) + (stats.get("down", 0) if stats else 0)
            total_bytes += used
            is_expired = exp > 0 and exp < now_ms
            if is_expired:
                expired += 1
            elif en:
                active += 1
            exp_str = datetime.fromtimestamp(exp / 1000).strftime("%d.%m.%Y") if exp > 0 else "Never"
            users.append({
                "email": email, "uuid": cid, "inbound_id": inb["id"],
                "proto": f'{inb["protocol"]}:{inb["port"]}',
                "traffic": fmt_bytes(used), "expiry_str": exp_str,
                "expired": is_expired, "enable": en,
                "vless_url": build_link(cid, email, inb),
                "sub_url": build_sub_url(sub_id),
            })

    flash_msg = request.args.get("flash", "")
    flash_type = request.args.get("ftype", "ok")
    return render_template_string(DASHBOARD_PAGE,
        users=users, inbounds=inbounds, active=active, expired=expired,
        total_tr=fmt_bytes(total_bytes), flash_msg=flash_msg, flash_type=flash_type)


@app.route("/add", methods=["POST"])
@login_required
def add_user():
    email = request.form.get("email", "").strip()
    inb_id = int(request.form.get("inbound_id", 1))
    days = int(request.form.get("expiry_days", 30))
    total_gb = int(request.form.get("total_gb", 0))
    if not email:
        return redir("", flash="Name required", ftype="er")
    inb = get_full_inbound(inb_id)
    if not inb:
        return redir("", flash="Inbound not found", ftype="er")
    settings = inb.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    settings["clients"].append({
        "id": str(uuid.uuid4()), "email": email, "enable": True,
        "expiryTime": int((time.time() + days * 86400) * 1000),
        "totalGB": total_gb, "limitIp": 0, "subId": email,
        "tgId": 0, "comment": "", "reset": 0, "security": "",
        "auth": secrets.token_hex(8), "password": secrets.token_hex(8),
        "created_at": int(time.time() * 1000), "updated_at": int(time.time() * 1000),
    })
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if result.get("success"):
        return redir("", flash=f"User {email} created", ftype="ok")
    return redir("", flash=f"Error: {result.get('msg', 'Unknown')}", ftype="er")


@app.route("/extend", methods=["POST"])
@login_required
def extend_user():
    email = request.form.get("email", "")
    inb_id = int(request.form.get("inbound_id", 1))
    cid = request.form.get("client_uuid", "")
    days = int(request.form.get("days", 30))
    inb = get_full_inbound(inb_id)
    if not inb:
        return redir("", flash="Inbound not found", ftype="er")
    settings = inb.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    now_ms = int(time.time() * 1000)
    found_client = None
    for c in settings.get("clients", []):
        if c.get("id") == cid or c.get("email") == email:
            cur_exp = c.get("expiryTime", 0)
            c["expiryTime"] = (cur_exp + days * 86400 * 1000) if cur_exp > now_ms else (now_ms + days * 86400 * 1000)
            c["updated_at"] = now_ms
            found_client = c
            break
    if not found_client:
        return redir("", flash="Client not found", ftype="er")
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if result.get("success"):
        new_date = datetime.fromtimestamp(found_client["expiryTime"] / 1000).strftime("%d.%m.%Y")
        return redir("", flash=f"{email} extended to {new_date}", ftype="ok")
    return redir("", flash=f"Error: {result.get('msg', 'Unknown')}", ftype="er")


@app.route("/delete", methods=["POST"])
@login_required
def delete_user():
    email = request.form.get("email", "")
    inb_id = int(request.form.get("inbound_id", 1))
    inb = get_full_inbound(inb_id)
    if not inb:
        return redir("", flash="Inbound not found", ftype="er")
    settings = inb.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    settings["clients"] = [c for c in settings.get("clients", []) if c.get("email") != email]
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if result.get("success"):
        return redir("", flash=f"User {email} deleted", ftype="ok")
    return redir("", flash=f"Error: {result.get('msg', 'Unknown')}", ftype="er")


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    print(f"\n{'='*50}")
    print(f"  Xray Panel v1.0")
    print(f"  3x-ui API:  {XUI['base_url']}")
    print(f"  Domain:     {PANEL_DOMAIN or '(auto-detect)'}")
    print(f"  Login:      {PANEL_USER}")
    print(f"  Port:       {FLASK_PORT}")
    if SECRET_PATH:
        print(f"  Secret:     /{SECRET_PATH}")
    print(f"{'='*50}\n")

    app.run(host="127.0.0.1", port=FLASK_PORT, debug=False)
