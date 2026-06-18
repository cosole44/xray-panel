#!/bin/bash
# ============================================================
# Xray Panel — Установщик
# Лёгкая панель управления пользователями Xray для 3x-ui
# https://github.com/cosole44/xray-panel
# ============================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║       ⚡ Xray Panel Installer        ║"
    echo "  ║   Панель управления пользователями   ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# --- Detect 3x-ui ---
detect_xui() {
    echo ""
    echo -e "${BLUE}── Обнаружение 3x-ui ──${NC}"

    XUI_BIN=""
    for p in /usr/local/x-ui/x-ui /usr/bin/x-ui; do
        [ -f "$p" ] && XUI_BIN="$p" && break
    done
    [ -z "$XUI_BIN" ] && { err "3x-ui не найден! Установите: bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)"; exit 1; }
    log "3x-ui найден: $XUI_BIN"

    XUI_SETTINGS=$($XUI_BIN setting -show 2>/dev/null || true)
    XUI_PORT=$(echo "$XUI_SETTINGS" | grep -oP 'port:\s*\K\d+' || echo "2053")
    XUI_BASEPATH=$(echo "$XUI_SETTINGS" | grep -oP 'webBasePath:\s*\K\S+' || echo "/")
    XUI_TOKEN=$($XUI_BIN setting -getApiToken 2>/dev/null | grep -oP 'apiToken:\s*\K\S+' || echo "")

    XUI_URL="https://127.0.0.1:${XUI_PORT}${XUI_BASEPATH}"
    [ "${XUI_BASEPATH}" = "/" ] && XUI_URL="https://127.0.0.1:${XUI_PORT}"

    log "Порт: ${XUI_PORT} | Base: ${XUI_BASEPATH}"
    [ -n "$XUI_TOKEN" ] && log "API токен: ${XUI_TOKEN:0:8}..." || warn "API токен не найден"
}

# --- Detect domain ---
detect_domain() {
    echo ""
    echo -e "${BLUE}── Обнаружение домена и SSL ──${NC}"

    DETECTED_DOMAIN=""
    DETECTED_CERT=""
    DETECTED_KEY=""

    for d in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*; do
        [ -f "$d" ] || continue
        DN=$(grep -oP 'server_name\s+\K[^;\s]+' "$d" 2>/dev/null | head -1)
        if [ -n "$DN" ] && echo "$DN" | grep -q '\.'; then
            DETECTED_DOMAIN="$DN"
            break
        fi
    done

    for d in /root/cert/*/; do
        [ -f "${d}fullchain.pem" ] && [ -f "${d}privkey.pem" ] && {
            DETECTED_CERT="${d}fullchain.pem"
            DETECTED_KEY="${d}privkey.pem"
            [ -z "$DETECTED_DOMAIN" ] && DETECTED_DOMAIN=$(basename "$d")
            break
        }
    done

    if [ -n "$DETECTED_DOMAIN" ]; then
        log "Домен: ${DETECTED_DOMAIN}"
    else
        warn "Домен не обнаружен"
    fi
    if [ -n "$DETECTED_CERT" ]; then
        log "Сертификат: ${DETECTED_CERT}"
    else
        warn "SSL сертификат не обнаружен"
    fi
}

# --- Interactive config ---
interactive_config() {
    echo ""
    echo -e "${BLUE}── Настройка панели ──${NC}"

    # Domain
    read -rp "Домен панели [${DETECTED_DOMAIN:-$(curl -s ifconfig.me 2>/dev/null || echo "localhost")}]: " INPUT_DOMAIN
    PANEL_DOMAIN="${INPUT_DOMAIN:-${DETECTED_DOMAIN:-$(curl -s ifconfig.me 2>/dev/null || echo "localhost")}}"

    # SSL port
    read -rp "Внешний HTTPS порт [8888]: " INPUT_SSL_PORT
    SSL_PORT="${INPUT_SSL_PORT:-8888}"

    # Flask port (internal)
    FLASK_PORT=8889

    # Username
    read -rp "Логин панели [admin]: " INPUT_USER
    PANEL_USER="${INPUT_USER:-admin}"

    # Password
    while true; do
        read -rsp "Пароль панели: " INPUT_PASS; echo
        [ -n "$INPUT_PASS" ] && break
        err "Пароль не может быть пустым"
    done
    while true; do
        read -rsp "Подтвердите пароль: " INPUT_PASS2; echo
        [ "$INPUT_PASS" = "$INPUT_PASS2" ] && break
        err "Пароли не совпадают"
    done

    # Secret path (like 3x-ui)
    SECRET_PATH=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

    echo ""
    echo -e "${BLUE}── Итоговая конфигурация ──${NC}"
    echo "  Домен:        ${PANEL_DOMAIN}"
    echo "  HTTPS порт:   ${SSL_PORT}"
    echo "  Внутренний:   ${FLASK_PORT}"
    echo "  Логин:        ${PANEL_USER}"
    PASS_MASK=$(printf '%*s' "${#INPUT_PASS}" '' | tr ' ' '*')
    echo "  Пароль:       ${PASS_MASK}"
    echo "  Секретный путь: /${SECRET_PATH}"
    echo ""
    read -rp "Продолжить установку? [Y/n]: " CONFIRM
    [ "${CONFIRM,,}" = "n" ] && { warn "Отмена"; exit 0; }
}

# --- Install ---
install_deps() {
    echo ""
    echo -e "${BLUE}── Установка зависимостей ──${NC}"
    apt-get update -qq 2>&1 | tail -3
    apt-get install -y -qq python3 python3-flask python3-requests nginx 2>&1 | tail -5
    log "Зависимости установлены"
}

install_panel() {
    echo ""
    echo -e "${BLUE}── Установка панели ──${NC}"

    INSTALL_DIR="/opt/xray-panel"
    mkdir -p "$INSTALL_DIR"

    # Copy app.py
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${SCRIPT_DIR}/app.py" ]; then
        cp "${SCRIPT_DIR}/app.py" "${INSTALL_DIR}/app.py"
    else
        err "app.py не найден в ${SCRIPT_DIR}"
        exit 1
    fi
    log "app.py скопирован"

    # Create systemd service
    cat > /etc/systemd/system/xray-panel.service << SVCEOF
[Unit]
Description=Xray Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="XPANEL_USER=${PANEL_USER}"
Environment="XPANEL_PASS=${INPUT_PASS}"
Environment="XPANEL_PORT=${FLASK_PORT}"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable xray-panel >/dev/null 2>&1
    log "Systemd сервис создан"
}

configure_nginx() {
    echo ""
    echo -e "${BLUE}── Настройка nginx ──${NC}"

    CERT_PATH="${DETECTED_CERT}"
    KEY_PATH="${DETECTED_KEY}"

    if [ -z "$CERT_PATH" ] || [ -z "$KEY_PATH" ]; then
        warn "SSL сертификат не найден — nginx не настроен"
        warn "Панель доступна по HTTP: http://127.0.0.1:${FLASK_PORT}"
        return
    fi

    # Remove old config if exists
    rm -f /etc/nginx/sites-enabled/xray-panel

    cat > /etc/nginx/sites-available/xray-panel << NGINXEOF
server {
    listen ${SSL_PORT} ssl http2;
    server_name ${PANEL_DOMAIN};

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location /${SECRET_PATH}/ {
        proxy_pass http://127.0.0.1:${FLASK_PORT}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
    }

    location / {
        return 404;
    }
}
NGINXEOF

    ln -sf /etc/nginx/sites-available/xray-panel /etc/nginx/sites-enabled/xray-panel

    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null
        log "Nginx настроен: https://${PANEL_DOMAIN}:${SSL_PORT}"
    else
        err "Ошибка конфигурации nginx"
        rm -f /etc/nginx/sites-enabled/xray-panel
    fi
}

start_panel() {
    echo ""
    echo -e "${BLUE}── Запуск ──${NC}"
    systemctl restart xray-panel
    sleep 1

    if systemctl is-active --quiet xray-panel; then
        log "Панель запущена!"
    else
        err "Ошибка запуска"
        journalctl -u xray-panel --no-pager -n 10
        exit 1
    fi
}

print_result() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ⚡ Xray Panel установлен!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  URL:    https://${PANEL_DOMAIN}:${SSL_PORT}${SECRET_PATH}"
    echo "  Логин:  ${PANEL_USER}"
    echo "  Пароль: ${INPUT_PASS}"
    echo ""
    echo "  3x-ui:  ${XUI_URL}"
    echo ""
    echo -e "${YELLOW}  Сохраните эти данные!${NC}"
    echo ""
    echo "  Управление:"
    echo "    systemctl restart xray-panel"
    echo "    systemctl status xray-panel"
    echo "    journalctl -u xray-panel -f"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
}

# --- Main ---
print_banner
detect_xui
detect_domain
interactive_config

echo ""
echo -e "${BLUE}── Установка ──${NC}"
install_deps || { err "Ошибка установки зависимостей"; exit 1; }
install_panel || { err "Ошибка установки панели"; exit 1; }
configure_nginx || { warn "Ошибка nginx (не критично)"; }
start_panel || { err "Ошибка запуска панели"; exit 1; }
print_result
