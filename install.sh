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

# ============================================================
# Cleanup old installation
# ============================================================
cleanup() {
    if systemctl is-enabled xray-panel 2>/dev/null || systemctl is-active xray-panel 2>/dev/null; then
        echo ""
        warn "Обнаружена предыдущая установка Xray Panel"
        read -rp "Удалить и переустановить? [Y/n]: " CLEANUP
        if [ "${CLEANUP,,}" != "n" ]; then
            echo ""
            echo -e "${BLUE}── Удаление старой установки ──${NC}"
            systemctl stop xray-panel 2>/dev/null || true
            systemctl disable xray-panel 2>/dev/null || true
            rm -f /etc/systemd/system/xray-panel.service
            systemctl daemon-reload 2>/dev/null || true
            rm -rf /opt/xray-panel
            rm -f /etc/nginx/sites-enabled/xray-panel
            systemctl reload nginx 2>/dev/null || true
            log "Старая установка удалена"
        fi
    fi
}

# ============================================================
# Detect 3x-ui
# ============================================================
detect_xui() {
    echo ""
    echo -e "${BLUE}── Обнаружение 3x-ui ──${NC}"

    XUI_BIN=""
    for p in /usr/local/x-ui/x-ui /usr/bin/x-ui; do
        [ -f "$p" ] && XUI_BIN="$p" && break
    done
    [ -z "$XUI_BIN" ] && { err "3x-ui не найден!"; exit 1; }
    log "3x-ui: $XUI_BIN"

    XUI_SETTINGS=$($XUI_BIN setting -show 2>/dev/null || true)
    XUI_PORT=$(echo "$XUI_SETTINGS" | grep -oP 'port:\s*\K\d+' || echo "2053")
    XUI_BASEPATH=$(echo "$XUI_SETTINGS" | grep -oP 'webBasePath:\s*\K\S+' || echo "/")
    XUI_TOKEN=$($XUI_BIN setting -getApiToken 2>/dev/null | grep -oP 'apiToken:\s*\K\S+' || echo "")

    # Build base URL: https://127.0.0.1:PORT/BASEPATH
    XUI_URL="https://127.0.0.1:${XUI_PORT}"
    if [ -n "$XUI_BASEPATH" ] && [ "$XUI_BASEPATH" != "/" ]; then
        # Strip trailing and leading slashes to avoid double slash
        CLEAN_PATH=$(echo "$XUI_BASEPATH" | sed 's:^/::;s:/$::')
        XUI_URL="${XUI_URL}/${CLEAN_PATH}"
    fi

    log "API: ${XUI_URL}"
    [ -n "$XUI_TOKEN" ] && log "Token: ${XUI_TOKEN:0:8}..." || warn "Token not found"
}

# ============================================================
# Detect domain and SSL certs
# ============================================================
detect_domain() {
    echo ""
    echo -e "${BLUE}── Обнаружение домена и SSL ──${NC}"

    DETECTED_DOMAIN=""
    DETECTED_CERT=""
    DETECTED_KEY=""

    # Find domain from nginx
    for d in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*; do
        [ -f "$d" ] || continue
        DN=$(grep -oP 'server_name\s+\K[^;\s]+' "$d" 2>/dev/null | head -1)
        if [ -n "$DN" ] && echo "$DN" | grep -q '\.'; then
            DETECTED_DOMAIN="$DN"
            break
        fi
    done

    # Find SSL certs
    for d in /root/cert/*/; do
        [ -f "${d}fullchain.pem" ] && [ -f "${d}privkey.pem" ] && {
            DETECTED_CERT="${d}fullchain.pem"
            DETECTED_KEY="${d}privkey.pem"
            [ -z "$DETECTED_DOMAIN" ] && DETECTED_DOMAIN=$(basename "$d")
            break
        }
    done

    [ -n "$DETECTED_DOMAIN" ] && log "Домен: ${DETECTED_DOMAIN}" || warn "Домен не найден"
    [ -n "$DETECTED_CERT" ] && log "Сертификат: ${DETECTED_CERT}" || warn "SSL не найден"
}

# ============================================================
# Interactive config
# ============================================================
interactive_config() {
    echo ""
    echo -e "${BLUE}── Настройка панели ──${NC}"

    # Domain
    DEFAULT_DOMAIN="${DETECTED_DOMAIN:-$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo "localhost")}"
    read -rp "Домен панели [${DEFAULT_DOMAIN}]: " INPUT_DOMAIN
    PANEL_DOMAIN="${INPUT_DOMAIN:-$DEFAULT_DOMAIN}"

    # SSL port
    read -rp "Внешний HTTPS порт [8888]: " INPUT_SSL_PORT
    SSL_PORT="${INPUT_SSL_PORT:-8888}"

    # Flask port (internal, always 8889)
    FLASK_PORT=8889

    # Username
    read -rp "Логин панели [admin]: " INPUT_USER
    PANEL_USER="${INPUT_USER:-admin}"

    # Password (required)
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
    SECRET_PATH=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || openssl rand -base64 16 | tr -d '/+=' | head -c 16)

    echo ""
    echo -e "${BLUE}── Итоговая конфигурация ──${NC}"
    echo "  Домен:          ${PANEL_DOMAIN}"
    echo "  HTTPS порт:     ${SSL_PORT}"
    echo "  Внутренний:     ${FLASK_PORT}"
    echo "  Логин:          ${PANEL_USER}"
    PASS_MASK=$(printf '%*s' "${#INPUT_PASS}" '' | tr ' ' '*')
    echo "  Пароль:         ${PASS_MASK}"
    echo "  Секретный путь: /${SECRET_PATH}"
    echo "  3x-ui API:      ${XUI_URL}"
    echo ""
    read -rp "Продолжить установку? [Y/n]: " CONFIRM
    [ "${CONFIRM,,}" = "n" ] && { warn "Отмена"; exit 0; }
}

# ============================================================
# Install dependencies
# ============================================================
install_deps() {
    echo ""
    echo -e "${BLUE}── Установка зависимостей ──${NC}"
    apt-get update -qq 2>&1 | tail -3
    apt-get install -y -qq python3 python3-flask python3-requests nginx 2>&1 | tail -5
    log "Зависимости установлены"
}

# ============================================================
# Install panel files
# ============================================================
install_panel() {
    echo ""
    echo -e "${BLUE}── Установка панели ──${NC}"

    INSTALL_DIR="/opt/xray-panel"
    mkdir -p "$INSTALL_DIR"

    # Copy app.py from git repo or current directory
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${SCRIPT_DIR}/app.py" ]; then
        cp "${SCRIPT_DIR}/app.py" "${INSTALL_DIR}/app.py"
    elif [ -f "${SCRIPT_DIR}/xray-panel/app.py" ]; then
        cp "${SCRIPT_DIR}/xray-panel/app.py" "${INSTALL_DIR}/app.py"
    else
        err "app.py не найден в ${SCRIPT_DIR}"
        exit 1
    fi
    log "app.py скопирован"

    # Verify app.py is complete (must contain app.run)
    if ! grep -q "app.run" "${INSTALL_DIR}/app.py"; then
        err "app.py повреждён (нет app.run)"
        exit 1
    fi
    log "app.py проверен"
}

# ============================================================
# Create systemd service
# ============================================================
create_service() {
    echo ""
    echo -e "${BLUE}── Создание systemd сервиса ──${NC}"

    # Re-read token fresh — it may have changed since initial detection
    XUI_BIN_CURRENT=""
    for p in /usr/local/x-ui/x-ui /usr/bin/x-ui; do
        [ -f "$p" ] && XUI_BIN_CURRENT="$p" && break
    done
    if [ -n "$XUI_BIN_CURRENT" ]; then
        XUI_TOKEN=$($XUI_BIN_CURRENT setting -getApiToken 2>/dev/null | grep -oP 'apiToken:\s*\K\S+' || echo "")
        log "Токен обновлён: ${XUI_TOKEN:0:8}..."
    fi

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
Environment="XPANEL_DOMAIN=${PANEL_DOMAIN}"
Environment="XPANEL_SECRET=${SECRET_PATH}"
Environment="XUI_BASE_URL=${XUI_URL}"
Environment="XUI_API_TOKEN=${XUI_TOKEN}"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable xray-panel >/dev/null 2>&1

    # Verify service file has all required env vars
    if ! grep -q 'XUI_BASE_URL=' /etc/systemd/system/xray-panel.service || \
       ! grep -q 'XUI_API_TOKEN=' /etc/systemd/system/xray-panel.service; then
        err "Service file missing XUI env vars!"
        exit 1
    fi
    log "Systemd сервис создан"
}

# ============================================================
# Configure nginx for HTTPS
# ============================================================
configure_nginx() {
    echo ""
    echo -e "${BLUE}── Настройка nginx ──${NC}"

    if [ -z "$DETECTED_CERT" ] || [ -z "$DETECTED_KEY" ]; then
        warn "SSL сертификат не найден — nginx не настроен"
        warn "Панель доступна по HTTP: http://127.0.0.1:${FLASK_PORT}"
        return
    fi

    rm -f /etc/nginx/sites-enabled/xray-panel

    cat > /etc/nginx/sites-available/xray-panel << NGINXEOF
server {
    listen ${SSL_PORT} ssl http2;
    server_name ${PANEL_DOMAIN};

    ssl_certificate ${DETECTED_CERT};
    ssl_certificate_key ${DETECTED_KEY};
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
        log "Nginx: https://${PANEL_DOMAIN}:${SSL_PORT}/${SECRET_PATH}/"
    else
        err "Ошибка конфигурации nginx"
        rm -f /etc/nginx/sites-enabled/xray-panel
    fi
}

# ============================================================
# Start panel
# ============================================================
start_panel() {
    echo ""
    echo -e "${BLUE}── Запуск ──${NC}"
    systemctl restart xray-panel
    sleep 2

    if systemctl is-active --quiet xray-panel; then
        log "Панель запущена!"
    else
        err "Ошибка запуска:"
        journalctl -u xray-panel --no-pager -n 10
        exit 1
    fi
}

# ============================================================
# Print result
# ============================================================
print_result() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ⚡ Xray Panel установлен!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  URL:    https://${PANEL_DOMAIN}:${SSL_PORT}/${SECRET_PATH}/"
    echo "  Логин:  ${PANEL_USER}"
    echo "  Пароль: ${INPUT_PASS}"
    echo ""
    echo "  3x-ui:  https://${PANEL_DOMAIN}/$(echo $XUI_BASEPATH | sed 's|^/||')/"
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

# ============================================================
# Main
# ============================================================
print_banner
cleanup
detect_xui
detect_domain
interactive_config
install_deps
install_panel
create_service
configure_nginx
start_panel
print_result
