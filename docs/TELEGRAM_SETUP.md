# Telegram — настройка Miharu

Документ для администраторов и разработчиков.  
Пользователю в офисной сборке достаточно кнопки **TELEGRAM** → **Start** в боте.

---

## Режимы уведомлений

| Режим | Когда | Где токен бота |
|-------|--------|----------------|
| **`direct`** | Офис / self-hosted / разработка | На каждом клиенте (из Setup или settings) |
| **`backend`** | Много пользователей, центральный сервис | Только на сервере |
| **`off`** | Без уведомлений | — |

Задаётся в `settings.json` → `notification_mode` или env `DISK_DIAGNOSTIC_NOTIFICATION_MODE`.

---

## Direct mode (типичный офис)

### Идея

- Один Telegram-бот на команду  
- Токен попадает в установщик через `secrets/product_defaults.json`  
- На каждом ПК пользователь жмёт **TELEGRAM** → **Start** → сохраняется свой `chat_id`

### Подготовка бота

1. В Telegram откройте [@BotFather](https://t.me/BotFather)  
2. `/newbot` — создайте бота, получите токен вида `123456:AA...`  
3. (Опционально) отключите group privacy, если нужен групповой чат  

### Токен в сборке

```powershell
# secrets/product_defaults.json  (НЕ коммитить)
{
  "telegram_bot_token": "YOUR_BOT_TOKEN",
  "notification_mode": "direct"
}
```

Или скопируйте шаблон:

```powershell
copy secrets\product_defaults.example.json secrets\product_defaults.json
# отредактируйте токен
```

При `.\build\build.ps1` файл попадёт в бандл.  
Если `product_defaults.json` нет — скрипт возьмёт `TELEGRAM_BOT_TOKEN` / `MIHARU_TELEGRAM_BOT_TOKEN` из env или скопирует example.

### Привязка на рабочем месте

1. Запуск Miharu  
2. Кнопка **TELEGRAM**  
3. В Telegram у бота — **Start**  
4. Диалог «Чат успешно привязан»

Приоритет чтения токена в рантайме:

1. `TELEGRAM_BOT_TOKEN` / `TELEGRAM_TOKEN` (env)  
2. `settings.json` → `telegram_bot_token`  
3. `product_defaults.json`  
4. `product_defaults.example.json` (только dev-fallback)

`chat_id` берётся из env `TELEGRAM_CHAT_ID` или из settings после привязки.

### Ручная настройка (без Setup)

`%LOCALAPPDATA%\DiskDiagnostic\Config\settings.json`:

```json
{
  "schema_version": 1,
  "notification_mode": "direct",
  "telegram_bot_token": "YOUR_BOT_TOKEN",
  "telegram_chat_id": "123456789"
}
```

Узнать chat_id: написать боту и посмотреть updates, или воспользоваться кнопкой TELEGRAM в приложении.

### Что уходит в Telegram

- Сводка после скана (если настроено)  
- Алерты: **HIGH**, новая **persistence** (autorun / task и т.п.) при Monitor  

Полный HTML-отчёт в Telegram **не** отправляется.

---

## Backend mode (рекомендуется для большого парка)

Клиент **не** хранит общий bot token.

```powershell
$env:DISK_DIAGNOSTIC_NOTIFICATION_MODE = "backend"
$env:DISK_DIAGNOSTIC_BACKEND_URL = "https://your-backend.example"
```

Клиент шлёт событие на backend; сервер сам пишет в Telegram.  
Контракт: [BACKEND_API.md](BACKEND_API.md)

---

## Режим off

```powershell
$env:DISK_DIAGNOSTIC_NOTIFICATION_MODE = "off"
```

Или `"notification_mode": "off"` в settings.  
Сканы, снимки и локальные отчёты продолжают работать.

---

## Данные на диске

```text
%LOCALAPPDATA%\DiskDiagnostic\
  Config\settings.json
  Config\installation_id
  Alerts\telegram_state.json
```

`installation_id` — случайный локальный ID (не email, не hostname). Нужен для backend и дедупликации.

---

## Безопасность

| Правило | |
|---------|--|
| Не коммитить | `secrets/product_defaults.json`, живые токены в example |
| Один бот на офис | Да; chat_id — на пользователя / ПК / группу |
| Утечка токена | Перевыпустить у BotFather (`/revoke`) |
| Production scale | Предпочтителен `backend` |

---

## Типичные ошибки

| Сообщение / симптом | Причина | Действие |
|---------------------|---------|----------|
| Bot token не задан | Нет product_defaults в сборке / settings | Пересобрать Setup с json или прописать токен |
| Таймаут привязки | Не нажали Start / сеть | Повторить TELEGRAM → Start за 2 минуты |
| Алерты не приходят | mode=off или нет chat_id | Проверить settings и кнопку TELEGRAM |
| Окно «Не отвечает» | Старая версия, сеть на UI-потоке | Обновить клиент |
