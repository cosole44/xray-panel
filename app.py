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
from flask import Flask, render_template_string, request, redirect, url_for, session, abort, jsonify

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


def detect_sub_config():
    sub_port, sub_path = 2096, "/sub/"
    try:
        import sqlite3
        conn = sqlite3.connect("/etc/x-ui/x-ui.db")
        for row in conn.execute("SELECT key, value FROM settings WHERE key IN ('subPort', 'subPath')"):
            if row[0] == "subPort": sub_port = int(row[1])
            if row[0] == "subPath": sub_path = row[1]
        conn.close()
    except Exception:
        pass
    return sub_port, sub_path


def build_sub_url(sub_id):
    sub_port, sub_path = detect_sub_config()
    return f"https://{PANEL_DOMAIN}:{sub_port}{sub_path}{sub_id}"


def _get_stats():
    """Rebuild stats from 3x-ui API."""
    resp = xui_api("GET", "/panel/api/inbounds/list")
    inbounds = resp.get("obj", []) if resp.get("success") else []
    users, active, disabled, total_bytes = [], 0, 0, 0
    now_ms = int(time.time() * 1000)
    for inb in inbounds:
        settings = inb.get("settings", {})
        if isinstance(settings, str):
            try: settings = json.loads(settings)
            except: settings = {}
        for c in settings.get("clients", []):
            email = c.get("email", "")
            cid = c.get("id", "")
            exp = c.get("expiryTime", 0)
            en = c.get("enable", True)
            sub_id = c.get("subId", email)
            stats = next((s for s in inb.get("clientStats", []) if s.get("email") == email), None)
            used = (stats.get("up", 0) if stats else 0) + (stats.get("down", 0) if stats else 0)
            total_bytes += used
            if not en: disabled += 1
            elif en: active += 1
            exp_str = datetime.fromtimestamp(exp / 1000).strftime("%d.%m.%Y") if exp > 0 else "Never"
            days_left = max(0, int((exp - now_ms) / 86400000)) if exp > 0 else 9999
            users.append({
                "email": email, "uuid": cid, "inbound_id": inb["id"],
                "traffic": fmt_bytes(used), "traffic_bytes": used,
                "expiry_str": exp_str, "expiry": exp if exp > 0 else 9999999999999,
                "days_left": days_left,
                "expired": not en, "enable": en,
                "vless_url": build_link(cid, email, inb),
                "sub_url": build_sub_url(sub_id),
            })
    return {"total": len(users), "active": active, "expired": disabled, "traffic": fmt_bytes(total_bytes), "users": users}


# ============================================================
# HTML Templates
# ============================================================
LOGIN_PAGE = '''<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Xray">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#000000">
<meta name="color-scheme" content="dark">
<title>Xray</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{background:#000;color-scheme:dark}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif;background:#000;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.box{background:#1c1c1e;border-radius:16px;padding:40px 28px;width:100%;max-width:380px}
h1{text-align:center;font-size:28px;font-weight:700;margin-bottom:4px}
.sub{text-align:center;color:#8e8e93;font-size:13px;margin-bottom:32px}
label{display:block;margin-bottom:6px;font-size:13px;color:#8e8e93;font-weight:500}
input{width:100%;padding:14px 16px;background:#2c2c2e;border:none;border-radius:12px;color:#fff;font-size:16px;outline:none;margin-bottom:14px;transition:background .2s}
input:focus{background:#3a3a3c}
.btn{width:100%;padding:15px;background:#0a84ff;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer;transition:all .15s;margin-top:4px}
.btn:active{transform:scale(0.98);opacity:0.8}
.err{background:rgba(255,69,58,0.15);color:#ff453a;padding:12px;border-radius:10px;margin-bottom:16px;font-size:13px;text-align:center}
</style></head><body>
<div class="box">
<h1>Xray</h1>
<p class="sub">Управление пользователями</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST"><label>Логин</label><input type="text" name="username" required autofocus>
<label>Пароль</label><input type="password" name="password" required>
<button type="submit" class="btn">Войти</button></form></div></body></html>'''

DASHBOARD_PAGE = '''<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Xray">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#000000">
<meta name="color-scheme" content="dark">
<title>Xray</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{background:#000;color-scheme:dark}
:root{--bg:#000;--card:#1c1c1e;--card2:#2c2c2e;--border:rgba(84,84,88,0.65);--text:#fff;--muted:#8e8e93;--blue:#0a84ff;--green:#30d158;--red:#ff453a;--orange:#ff9f0a;--yellow:#ffd60a;--radius:13px}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif;background:linear-gradient(160deg,#0a0a0a 0%,#0d1117 40%,#0a0a0a 100%);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
.header{background:rgba(28,28,30,0.92);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:0.5px solid var(--border);padding:14px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:17px;font-weight:600}
.hdr-right{display:flex;gap:8px;align-items:center}
.container{max-width:500px;margin:0 auto;padding:16px;padding-bottom:100px}
.section-label{font-size:13px;color:var(--muted);font-weight:500;margin:20px 0 8px 4px;text-transform:uppercase;letter-spacing:0.5px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
@media(max-width:500px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--card);border-radius:var(--radius);padding:14px 10px;text-align:center}
.stat .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px}
.stat .value{font-size:22px;font-weight:700}
.stat:active{transform:scale(0.95)}
.stat .value.g{color:var(--green)}.stat .value.b{color:var(--blue)}.stat .value.p{color:#bf5af2}.stat .value.r{color:var(--red)}.stat .value.y{color:var(--yellow)}
.add-btn{width:100%;padding:14px;background:var(--blue);color:#fff;border:none;border-radius:var(--radius);font-size:16px;font-weight:600;cursor:pointer;transition:all .15s;margin-bottom:20px}
.add-btn:active{transform:scale(0.98);opacity:0.8}
.search-bar{display:flex;gap:10px;margin-bottom:16px}
.search-bar input{flex:1;padding:10px 14px;background:var(--card2);border:none;border-radius:10px;color:var(--text);font-size:15px;outline:none}
.search-bar select{padding:10px 14px;background:var(--card2);border:none;border-radius:10px;color:var(--text);font-size:13px;outline:none;-webkit-appearance:none;min-width:120px}
.btn-refresh{width:40px;height:40px;background:var(--card2);border:none;border-radius:10px;color:var(--muted);font-size:18px;cursor:pointer;transition:all .15s;flex-shrink:0}
.btn-refresh:active{transform:scale(0.9);background:#3a3a3c}
.inbound-group{margin-bottom:20px}
.inbound-header{padding:12px 16px;background:var(--card);border-radius:var(--radius);display:flex;align-items:center;justify-content:space-between;cursor:pointer}
.inbound-header h3{font-size:15px;font-weight:600;display:flex;align-items:center;gap:6px}
.inbound-header .count{color:var(--muted);font-size:13px;font-weight:400}
.inbound-header .arrow{color:var(--muted);transition:transform .2s;font-size:12px}
.inbound-header.collapsed .arrow{transform:rotate(-90deg)}
.inbound-users{margin-top:2px}
.inbound-users.hidden{display:none}
.user-card{background:rgba(28,28,30,0.85);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-radius:var(--radius);padding:14px 16px;margin-bottom:2px;transition:transform .2s ease,box-shadow .2s ease}
.user-card:last-child{margin-bottom:0}
.user-card:hover{transform:scale(1.1);box-shadow:0 4px 24px rgba(10,132,255,0.15)}
.card-enter{opacity:0;transform:scale(0.5) translateY(20px)}
.card-enter.active{opacity:1;transform:scale(1) translateY(0);transition:opacity .35s ease,transform .35s ease}
.user-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.user-name{font-size:16px;font-weight:600}
.user-meta{display:flex;gap:16px;font-size:13px;color:var(--muted);margin-bottom:10px}
.c-green{color:var(--green)}.c-yellow{color:var(--yellow)}.c-red{color:var(--red)}
.user-card.is-online{border-left:3px solid var(--green)}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600}
.badge.g{background:rgba(48,209,88,0.18);color:var(--green)}.badge.r{background:rgba(255,69,58,0.18);color:var(--red)}
.badge.o{background:rgba(255,159,10,0.18);color:var(--orange)}.badge.i{background:rgba(142,142,147,0.18);color:var(--muted)}
.toggle{position:relative;width:51px;height:31px;cursor:pointer;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle .slider{position:absolute;inset:0;background:var(--card2);border-radius:31px;transition:.3s}
.toggle .slider::before{content:'';position:absolute;width:27px;height:27px;left:2px;bottom:2px;background:#fff;border-radius:50%;transition:.3s;box-shadow:0 2px 4px rgba(0,0,0,0.2)}
.toggle input:checked+.slider{background:var(--green)}
.toggle input:checked+.slider::before{transform:translateX(20px)}
.user-actions{display:flex;gap:8px;align-items:center}
.user-actions .spacer{flex:1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:8px 14px;border-radius:8px;font-size:13px;font-weight:500;border:none;cursor:pointer;transition:all .15s;background:var(--card2);color:var(--blue)}
.btn:active{transform:scale(0.95);opacity:0.7}
.btn-red{color:var(--red)}
.btn-full{width:100%}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);z-index:200;align-items:flex-end;justify-content:center;padding:0}
.modal-bg.on{display:flex}
@media(min-width:600px){.modal-bg{align-items:center;padding:16px}}
.modal{background:var(--card);border-radius:20px 20px 0 0;padding:20px 20px 32px;width:100%;max-width:500px;max-height:90vh;overflow-y:auto;animation:slideUp .25s ease}
@media(min-width:600px){.modal{border-radius:20px}}
@keyframes slideUp{from{transform:translateY(30px);opacity:0}to{transform:translateY(0);opacity:1}}
.modal-handle{width:36px;height:5px;background:rgba(142,142,147,0.3);border-radius:3px;margin:0 auto 16px;display:block}
.modal h3{font-size:18px;font-weight:600;margin-bottom:20px;text-align:center}
.fg{margin-bottom:16px}
.fg label{display:block;margin-bottom:6px;font-size:13px;color:var(--muted);font-weight:500}
.fg input,.fg select{width:100%;padding:12px 14px;background:var(--card2);border:none;border-radius:10px;color:var(--text);font-size:15px;outline:none;transition:background .2s;-webkit-appearance:none}
.fg input:focus,.fg select:focus{background:#3a3a3c}
.fg select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%238e8e93'%3E%3Cpath d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
.fa{display:flex;gap:10px;margin-top:20px}
.fa .btn{flex:1;padding:14px;font-size:16px;font-weight:600}
.btn-primary{background:var(--blue);color:#fff}
.btn-cancel{background:var(--card2);color:var(--text)}
.sub-url{background:var(--card2);border-radius:10px;padding:12px;font-family:'SF Mono',Monaco,monospace;font-size:11px;word-break:break-all;cursor:pointer;transition:background .2s;line-height:1.5;color:var(--text)}
.sub-url:active{background:#3a3a3c}
.empty{text-align:center;padding:40px 20px;color:var(--muted);font-size:15px}
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:12px 24px;border-radius:12px;font-size:14px;font-weight:600;z-index:999;animation:toastIn .3s;box-shadow:0 8px 25px rgba(0,0,0,0.4)}
.toast.ok{background:var(--green);color:#fff}
.toast.er{background:var(--red);color:#fff}
@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(-10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
.btn-load{opacity:0.5;pointer-events:none}
.hdr-exit{background:rgba(142,142,147,0.12);color:var(--muted);padding:6px 14px;border-radius:20px;font-size:13px;font-weight:500;text-decoration:none;transition:all .15s}
.hdr-exit:active{background:rgba(142,142,147,0.25);transform:scale(0.95)}
</style></head><body>
<div class="header">
<h1>Xray</h1>
<div class="hdr-right">
<a href="{{ basepath }}/logout" class="hdr-exit">Выйти</a>
</div></div>
<div class="container">
<div class="stats">
<div class="stat"><div class="label">Всего</div><div class="value b" id="stat-total">{{ users|length }}</div></div>
<div class="stat" onclick="pollOnline()" style="cursor:pointer"><div class="label">Онлайн</div><div class="value g" id="stat-online">0</div></div>
<div class="stat"><div class="label">Истёкшие</div><div class="value r" id="stat-expired">{{ expired }}</div></div>
<div class="stat"><div class="label">Трафик</div><div class="value y" id="stat-traffic">{{ total_tr }}</div></div>
</div>
<button class="add-btn" onclick="showModal('m-add')">Добавить пользователя</button>
<div class="search-bar">
<input type="text" id="searchInput" placeholder="Поиск..." oninput="filterUsers()">
<select id="sortBy" onchange="sortUsers()">
<option value="name">Имя A-Я</option>
<option value="name-desc">Имя Я-А</option>
<option value="traffic">Трафик</option>
<option value="expiry">Срок</option>
<option value="online">Онлайн</option>
</select>
<button class="btn-refresh" onclick="location.reload()" title="Обновить">&#8635;</button>
</div>
{% for inb in inbounds %}
{% set inb_users = users | selectattr("inbound_id", "equalto", inb.id) | list %}
<div class="inbound-group" id="group-{{ inb.id }}">
<div class="inbound-header" onclick="toggleInbound({{ inb.id }})">
<h3>{{ inb.remark }} <span class="count" id="count-{{ inb.id }}">{{ inb_users|length }}</span></h3>
<span class="arrow">&#9662;</span>
</div>
<div class="inbound-users" id="inbound-{{ inb.id }}">
{% for u in inb_users %}
<div class="user-card" id="user-{{ u.uuid }}" data-name="{{ u.email|lower }}" data-traffic="{{ u.traffic_bytes }}" data-expiry="{{ u.expiry }}" data-online="0">
<div class="user-top">
<div class="user-name">{{ u.email }} {% if not u.enable %}<span class="badge r">Выкл</span>{% else %}<span class="badge g">Активен</span>{% endif %}</div>
<label class="toggle" onclick="event.stopPropagation()"><input type="checkbox" {% if u.enable %}checked{% endif %} onchange="toggleUser('{{ u.email }}',{{ u.inbound_id }},'{{ u.uuid }}',this.checked)"><span class="slider"></span></label>
</div>
<div class="user-meta"><span>{{ u.traffic }}</span><span class="{% if u.days_left <= 1 %}c-red{% elif u.days_left <= 5 %}c-yellow{% else %}c-green{% endif %}">{% if u.days_left >= 9999 %}∞{% else %}{{ u.days_left }} дн.{% endif %}</span></div>
<div class="user-actions">
<button class="btn" onclick="showLinks('{{ u.email }}','{{ u.vless_url|e }}','{{ u.sub_url|e }}')">Ссылки</button>
<button class="btn" onclick="showExtend('{{ u.email }}','{{ u.inbound_id }}','{{ u.uuid }}')">Продлить</button>
<button class="btn btn-red" onclick="delUser('{{ u.email }}','{{ u.inbound_id }}','{{ u.uuid }}')">Удалить</button>
</div></div>
{% endfor %}
{% if not inb_users %}<div class="empty">Нет пользователей</div>{% endif %}
</div></div>
{% endfor %}

<div class="modal-bg" id="m-add" onclick="if(event.target===this)hideModal('m-add')">
<div class="modal"><span class="modal-handle"></span><h3>Новый пользователь</h3>
<div class="fg"><label>Имя</label><input type="text" id="add-email" required placeholder="например ivan"></div>
<div class="fg"><label>Срок (дней)</label><input type="number" id="add-days" value="30" min="1"></div>
<div class="fg"><label>Inbound</label><select id="add-inbound">{% for i in inbounds %}<option value="{{ i.id }}">{{ i.remark }}</option>{% endfor %}</select></div>
<div class="fa"><button type="button" class="btn btn-cancel" onclick="hideModal('m-add')">Отмена</button><button type="button" class="btn btn-primary" id="btn-add" onclick="doAdd()">Создать</button></div>
</div></div>

<div class="modal-bg" id="m-ext" onclick="if(event.target===this)hideModal('m-ext')">
<div class="modal"><span class="modal-handle"></span><h3>Продление подписки</h3>
<input type="hidden" id="ext-email"><input type="hidden" id="ext-inbound"><input type="hidden" id="ext-uuid">
<div class="fg"><label>Дней</label><input type="number" id="ext-days" value="30" min="1" oninput="syncDateFromDays()"></div>
<div class="fg"><label>Новая дата</label><input type="date" id="ext-date" oninput="syncDaysFromDate()"></div>
<div class="fa"><button type="button" class="btn btn-cancel" onclick="hideModal('m-ext')">Отмена</button><button type="button" class="btn btn-primary" id="btn-ext" onclick="doExtend()">Продлить</button></div>
</div></div>

<div class="modal-bg" id="m-links" onclick="if(event.target===this)hideModal('m-links')">
<div class="modal"><span class="modal-handle"></span><h3>Ссылки</h3>
<p style="color:var(--muted);font-size:13px;margin-bottom:12px" id="links-user"></p>
<div class="fg"><label>VLESS</label><div class="sub-url" id="link-vless" onclick="copyEl(this)"></div></div>
<div class="fg"><label>Подписка</label><div class="sub-url" id="link-sub" onclick="copyEl(this)"></div></div>
<div class="fa"><button type="button" class="btn btn-cancel btn-full" onclick="hideModal('m-links')">Закрыть</button></div>
</div></div>

<div class="modal-bg" id="m-welcome" onclick="if(event.target===this)hideModal('m-welcome')">
<div class="modal"><span class="modal-handle"></span><h3>Пользователь создан</h3>
<div style="font-size:14px;line-height:1.7;color:var(--text);margin-bottom:16px">
Вот <a href="https://teletype.in/@sorokin_xd/yZeNii7Icsz" target="_blank" style="color:var(--blue)">инструкция</a> как все установить, там все описано<br><br>
Вот твоя ссылка которую нужно будет в приложение добавить:<br>
<div class="sub-url" style="margin:8px 0;cursor:pointer" onclick="copyEl(this)" id="welcome-sub"></div><br>
Оплата: 79502435734 (Тинькофф)<br>
Олег С.<br>
100₽/мес
</div>
<div class="fa"><button type="button" class="btn btn-primary btn-full" onclick="copyWelcome()">Скопировать</button></div>
<div class="fa" style="margin-top:8px"><button type="button" class="btn btn-cancel btn-full" onclick="hideModal('m-welcome')">Закрыть</button></div>
</div></div>

<script>
var BP="{{ basepath }}";
function showModal(id){document.getElementById(id).classList.add('on')}
function hideModal(id){document.getElementById(id).classList.remove('on')}
function toast(msg,ok){var t=document.createElement('div');t.className='toast '+(ok?'ok':'er');t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),2500)}
function showExtend(e,i,u){document.getElementById('ext-email').value=e;document.getElementById('ext-inbound').value=i;document.getElementById('ext-uuid').value=u;
var now=new Date();var exp=new Date(now.getTime()+30*86400000);
document.getElementById('ext-days').value=30;document.getElementById('ext-date').value=exp.toISOString().split('T')[0];showModal('m-ext')}
function syncDateFromDays(){var d=parseInt(document.getElementById('ext-days').value)||0;var now=new Date();now.setDate(now.getDate()+d);document.getElementById('ext-date').value=now.toISOString().split('T')[0]}
function syncDaysFromDate(){var ds=document.getElementById('ext-date').value;if(!ds)return;var diff=Math.ceil((new Date(ds)-new Date())/(86400000));if(diff>0)document.getElementById('ext-days').value=diff}
function showLinks(e,v,s){document.getElementById('links-user').textContent=e;document.getElementById('link-vless').textContent=v;document.getElementById('link-sub').textContent=s;showModal('m-links')}
function copyEl(el){navigator.clipboard.writeText(el.textContent).then(()=>{toast('Скопировано',true)})}
function copyWelcome(){var url=document.getElementById('welcome-sub').textContent;var t='Инструкция как все установить: https://teletype.in/@sorokin_xd/yZeNii7Icsz\\n\\nТвоя ссылка для приложения:\\n`'+url+'`\\n\\nОплата: 79502435734(Тинькофф)\\nОлег С.\\n100₽/мес';navigator.clipboard.writeText(t).then(()=>{toast('Скопировано',true)})}
function toggleInbound(id){var el=document.getElementById('inbound-'+id);var hdr=el.previousElementSibling;el.classList.toggle('hidden');hdr.classList.toggle('collapsed')}
function filterUsers(){var q=document.getElementById('searchInput').value.toLowerCase();document.querySelectorAll('.user-card').forEach(c=>{c.style.display=c.dataset.name.includes(q)?'':'none'})}
function sortUsers(){var s=document.getElementById('sortBy').value;document.querySelectorAll('.inbound-users').forEach(g=>{var cards=Array.from(g.querySelectorAll('.user-card'));cards.sort((a,b)=>{if(s==='name')return a.dataset.name.localeCompare(b.dataset.name);if(s==='name-desc')return b.dataset.name.localeCompare(a.dataset.name);if(s==='traffic')return parseInt(b.dataset.traffic)-parseInt(a.dataset.traffic);if(s==='expiry')return parseInt(b.dataset.expiry)-parseInt(a.dataset.expiry);if(s==='online')return parseInt(b.dataset.online)-parseInt(a.dataset.online);return 0});cards.forEach(c=>g.appendChild(c))})}
async function api(path,body){var r=await fetch(BP+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});return await r.json()}
async function doAdd(){
var btn=document.getElementById('btn-add');btn.classList.add('btn-load');btn.textContent='Создание...';
var d=await api('/api/add',{email:document.getElementById('add-email').value,days:parseInt(document.getElementById('add-days').value),inbound_id:parseInt(document.getElementById('add-inbound').value)});
btn.classList.remove('btn-load');btn.textContent='Создать';
if(d.ok){hideModal('m-add');toast(d.user.email+' создан',true);addUserCard(d.user,d.inbound);document.getElementById('add-email').value='';updateStats(d.stats);document.getElementById('welcome-sub').textContent=d.user.sub_url;showModal('m-welcome')}
else toast(d.msg||'Ошибка',false)}
async function doExtend(){
var btn=document.getElementById('btn-ext');btn.classList.add('btn-load');btn.textContent='Продление...';
var d=await api('/api/extend',{email:document.getElementById('ext-email').value,inbound_id:parseInt(document.getElementById('ext-inbound').value),client_uuid:document.getElementById('ext-uuid').value,days:parseInt(document.getElementById('ext-days').value),expiry_date:document.getElementById('ext-date').value});
btn.classList.remove('btn-load');btn.textContent='Продлить';
if(d.ok){hideModal('m-ext');toast(d.user.email+' продлён до '+d.user.expiry_str,true);updateUserCard(d.user)}
else toast(d.msg||'Ошибка',false)}
async function toggleUser(email,inbound_id,uuid,enable){
var d=await api('/api/toggle',{email:email,inbound_id:inbound_id,client_uuid:uuid,enable:enable});
if(d.ok){updateUserCard(d.user);updateStats(d.stats);toast(email+(enable?' включён':' выключен'),true)}
else{toast(d.msg||'Ошибка',false);location.reload()}}
async function delUser(email,inbound_id,uuid){
if(!confirm('Удалить '+email+'?'))return;
var d=await api('/api/delete',{email:email,inbound_id:inbound_id,client_uuid:uuid});
if(d.ok){toast(email+' удалён',true);var el=document.getElementById('user-'+uuid);if(el)el.remove();updateStats(d.stats)}
else toast(d.msg||'Ошибка',false)}
function addUserCard(u,inb){var g=document.getElementById('inbound-'+u.inbound_id);if(!g){location.reload();return}
var h='<div class="user-card" id="user-'+u.uuid+'" data-name="'+u.email.toLowerCase()+'" data-traffic="'+u.traffic_bytes+'" data-expiry="'+u.expiry+'" data-online="0">';
h+='<div class="user-top"><div class="user-name">'+u.email+' '+(u.enable?'<span class="badge g">Активен</span>':'<span class="badge r">Выкл</span>')+'</div>';
h+='<label class="toggle" onclick="event.stopPropagation()"><input type="checkbox" '+(u.enable?'checked':'')+' onchange="toggleUser(this.dataset.email,this.dataset.iid,this.dataset.uid,this.checked)" data-email="'+u.email+'" data-iid="'+u.inbound_id+'" data-uid="'+u.uuid+'"><span class="slider"></span></label></div>';
h+='<div class="user-meta"><span>'+u.traffic+'</span><span class="'+(u.days_left<=1?'c-red':u.days_left<=5?'c-yellow':'c-green')+'">'+(u.days_left>=9999?'∞':u.days_left+' дн.')+'</span></div>';
h+='<div class="user-actions">';
h+='<button class="btn" onclick="showLinks(this.dataset.email,this.dataset.vless,this.dataset.sub)" data-email="'+u.email+'" data-vless="'+u.vless_url+'" data-sub="'+u.sub_url+'">Ссылки</button>';
h+='<button class="btn" onclick="showExtend(this.dataset.email,this.dataset.iid,this.dataset.uid)" data-email="'+u.email+'" data-iid="'+u.inbound_id+'" data-uid="'+u.uuid+'">Продлить</button>';
h+='<button class="btn btn-red" onclick="delUser(this.dataset.email,this.dataset.iid,this.dataset.uid)" data-email="'+u.email+'" data-iid="'+u.inbound_id+'" data-uid="'+u.uuid+'">Удалить</button></div></div>';
var empty=g.querySelector('.empty');if(empty)empty.remove();g.insertAdjacentHTML('beforeend',h);addUserCardReveal(document.getElementById('user-'+u.uuid))}
function updateUserCard(u){var el=document.getElementById('user-'+u.uuid);if(!el)return;
el.dataset.expiry=u.expiry;el.dataset.status=u.enable?(u.expired?'2':'1'):'3';
el.querySelector('.user-name').innerHTML=u.email+' '+(u.enable?'<span class="badge g">Активен</span>':'<span class="badge r">Выкл</span>');
el.querySelector('.user-meta').innerHTML='<span>'+u.traffic+'</span><span class="'+(u.days_left<=1?'c-red':u.days_left<=5?'c-yellow':'c-green')+'">'+(u.days_left>=9999?'∞':u.days_left+' дн.')+'</span>';
var cb=el.querySelector('.toggle input');if(cb)cb.checked=u.enable}
function updateStats(s){document.getElementById('stat-total').textContent=s.total;document.getElementById('stat-expired').textContent=s.expired;document.getElementById('stat-traffic').textContent=s.traffic;}
function initReveal(){var obs=new IntersectionObserver(function(entries){entries.forEach(function(e){if(e.isIntersecting){e.target.classList.add('active')}else{e.target.classList.remove('active')}})},{threshold:0.05});document.querySelectorAll('.user-card').forEach(function(c){c.classList.add('card-enter');obs.observe(c)});window._revealObs=obs}
function addUserCardReveal(el){el.classList.add('card-enter');requestAnimationFrame(function(){requestAnimationFrame(function(){el.classList.add('active')})});if(window._revealObs)window._revealObs.observe(el)}
document.addEventListener('DOMContentLoaded',initReveal);
async function pollOnline(){try{var r=await fetch(BP+'/api/online');var d=await r.json();if(d.ok){document.getElementById('stat-online').textContent=d.online.length;document.querySelectorAll('.user-card').forEach(function(c){var isOn=d.online.some(function(e){return e.toLowerCase()===c.dataset.name});c.dataset.online=isOn?'1':'0';if(isOn)c.classList.add('is-online');else c.classList.remove('is-online')})}}catch(e){}}
setInterval(pollOnline,15000);pollOnline();
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

    users, active, disabled, total_bytes = [], 0, 0, 0
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
            if not en:
                disabled += 1
            elif en:
                active += 1
            exp_str = datetime.fromtimestamp(exp / 1000).strftime("%d.%m.%Y") if exp > 0 else "Never"
            days_left = max(0, int((exp - now_ms) / 86400000)) if exp > 0 else 9999
            users.append({
                "email": email, "uuid": cid, "inbound_id": inb["id"],
                "proto": f'{inb["protocol"]}:{inb["port"]}',
                "traffic": fmt_bytes(used), "traffic_bytes": used,
                "expiry_str": exp_str, "expiry": exp if exp > 0 else 9999999999999,
                "days_left": days_left,
                "expired": not en, "enable": en,
                "vless_url": build_link(cid, email, inb),
                "sub_url": build_sub_url(sub_id),
            })

    flash_msg = request.args.get("flash", "")
    flash_type = request.args.get("ftype", "ok")
    return render_template_string(DASHBOARD_PAGE,
        users=users, inbounds=inbounds, active=active, expired=disabled,
        total_tr=fmt_bytes(total_bytes), flash_msg=flash_msg, flash_type=flash_type,
        basepath=BASEPATH)


@app.route("/api/add", methods=["POST"])
@login_required
def api_add():
    d = request.get_json()
    email = d.get("email", "").strip()
    inb_id = int(d.get("inbound_id", 1))
    days = int(d.get("days", 30))
    total_gb = int(d.get("total_gb", 0))
    if not email:
        return jsonify({"ok": False, "msg": "Name required"})
    inb = get_full_inbound(inb_id)
    if not inb:
        return jsonify({"ok": False, "msg": "Inbound not found"})
    settings = inb.get("settings", {})
    if isinstance(settings, str): settings = json.loads(settings)
    new_uuid = str(uuid.uuid4())
    settings["clients"].append({
        "id": new_uuid, "email": email, "enable": True,
        "expiryTime": int((time.time() + days * 86400) * 1000),
        "totalGB": total_gb, "limitIp": 0, "subId": email,
        "tgId": 0, "comment": "", "reset": 0, "security": "",
        "auth": secrets.token_hex(8), "password": secrets.token_hex(8),
        "created_at": int(time.time() * 1000), "updated_at": int(time.time() * 1000),
    })
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if not result.get("success"):
        return jsonify({"ok": False, "msg": result.get("msg", "Unknown error")})
    exp_ms = int((time.time() + days * 86400) * 1000)
    return jsonify({
        "ok": True,
        "user": {
            "uuid": new_uuid, "email": email, "inbound_id": inb_id,
            "enable": True, "expired": False, "expiry": exp_ms,
            "expiry_str": datetime.fromtimestamp(exp_ms / 1000).strftime("%d.%m.%Y"),
            "traffic": "0 B", "traffic_bytes": 0,
            "vless_url": build_link(new_uuid, email, inb),
            "sub_url": build_sub_url(email),
        },
        "inbound": {"id": inb["id"], "remark": inb.get("remark", ""), "protocol": inb["protocol"], "port": inb["port"]},
        "stats": _get_stats(),
    })


@app.route("/api/extend", methods=["POST"])
@login_required
def api_extend():
    d = request.get_json()
    email = d.get("email", "")
    inb_id = int(d.get("inbound_id", 1))
    cid = d.get("client_uuid", "")
    days = int(d.get("days", 30))
    expiry_date = d.get("expiry_date", "")
    inb = get_full_inbound(inb_id)
    if not inb:
        return jsonify({"ok": False, "msg": "Inbound not found"})
    settings = inb.get("settings", {})
    if isinstance(settings, str): settings = json.loads(settings)
    now_ms = int(time.time() * 1000)
    found = None
    for c in settings.get("clients", []):
        if c.get("id") == cid or c.get("email") == email:
            if expiry_date:
                new_exp = int(datetime.strptime(expiry_date, "%Y-%m-%d").timestamp() * 1000)
            else:
                cur_exp = c.get("expiryTime", 0)
                new_exp = (cur_exp + days * 86400 * 1000) if cur_exp > now_ms else (now_ms + days * 86400 * 1000)
            c["expiryTime"] = new_exp
            c["enable"] = True
            c["updated_at"] = now_ms
            found = c
            break
    if not found:
        return jsonify({"ok": False, "msg": "Client not found"})
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if not result.get("success"):
        return jsonify({"ok": False, "msg": result.get("msg", "Unknown error")})
    stats = _get_stats()
    user_stats = next((u for u in stats["users"] if u["email"] == email), None)
    return jsonify({"ok": True, "user": user_stats, "stats": stats})


@app.route("/api/toggle", methods=["POST"])
@login_required
def api_toggle():
    d = request.get_json()
    email = d.get("email", "")
    inb_id = int(d.get("inbound_id", 1))
    cid = d.get("client_uuid", "")
    enable = d.get("enable", True)
    inb = get_full_inbound(inb_id)
    if not inb:
        return jsonify({"ok": False, "msg": "Inbound not found"})
    settings = inb.get("settings", {})
    if isinstance(settings, str): settings = json.loads(settings)
    now_ms = int(time.time() * 1000)
    found = None
    for c in settings.get("clients", []):
        if c.get("id") == cid or c.get("email") == email:
            c["enable"] = enable
            c["updated_at"] = now_ms
            found = c
            break
    if not found:
        return jsonify({"ok": False, "msg": "Client not found"})
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if not result.get("success"):
        return jsonify({"ok": False, "msg": result.get("msg", "Unknown error")})
    stats = _get_stats()
    user_stats = next((u for u in stats["users"] if u["email"] == email), None)
    return jsonify({"ok": True, "user": user_stats, "stats": stats})


@app.route("/api/online", methods=["GET"])
@login_required
def api_online():
    resp = xui_api("GET", "/panel/api/inbounds/list")
    inbounds = resp.get("obj", []) if resp.get("success") else []
    now_ms = int(time.time() * 1000)
    ONLINE_THRESHOLD = 5 * 60 * 1000
    online = []
    for inb in inbounds:
        for s in inb.get("clientStats", []):
            last = s.get("lastOnline", 0)
            if last and (now_ms - last) < ONLINE_THRESHOLD:
                online.append(s.get("email", ""))
    return jsonify({"ok": True, "online": online})


@app.route("/api/delete", methods=["POST"])
@login_required
def api_delete():
    d = request.get_json()
    email = d.get("email", "")
    inb_id = int(d.get("inbound_id", 1))
    inb = get_full_inbound(inb_id)
    if not inb:
        return jsonify({"ok": False, "msg": "Inbound not found"})
    settings = inb.get("settings", {})
    if isinstance(settings, str): settings = json.loads(settings)
    settings["clients"] = [c for c in settings.get("clients", []) if c.get("email") != email]
    inb["settings"] = settings
    result = update_full_inbound(inb)
    if not result.get("success"):
        return jsonify({"ok": False, "msg": result.get("msg", "Unknown error")})
    return jsonify({"ok": True, "stats": _get_stats()})


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
