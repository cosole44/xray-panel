# Xray Panel

Лёгкая панель управления пользователями Xray для 3x-ui.

## Возможности

- Просмотр списка пользователей (статус, трафик, дата окончания)
- Добавление новых пользователей
- Продление срока действия
- Удаление пользователей
- Просмотр vless:// и subscription ссылок
- Авто-обнаружение 3x-ui (API, порт, домен, SSL)
- Мобильный-friendly тёмный интерфейс
- HTTPS через nginx

## Быстрая установка

```bash
git clone https://github.com/cosole44/xray-panel.git
cd xray-panel
bash install.sh
```

Установщик задаст вопросы:
- Домен панели (авто-определение из nginx)
- HTTPS порт (по умолчанию 8888)
- Логин и пароль

## Ручная установка

```bash
# Зависимости
apt install python3 python3-flask python3-requests nginx

# Запуск
XPANEL_USER=admin XPANEL_PASS=mypass python3 app.py
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `XPANEL_USER` | `admin` | Логин |
| `XPANEL_PASS` | `admin123` | Пароль |
| `XPANEL_PORT` | `8889` | Порт Flask |
| `XPANEL_DOMAIN` | (авто) | Домен панели |
| `XPANEL_SECRET` | (авто) | Секретный путь |

## Управление сервисом

```bash
systemctl restart xray-panel    # перезапуск
systemctl status xray-panel     # статус
journalctl -u xray-panel -f     # логи
```

## Требования

- Python 3.8+
- 3x-ui с включённым API
- SSL сертификат (Let's Encrypt и т.д.)
- nginx (для HTTPS)

## Лицензия

MIT
