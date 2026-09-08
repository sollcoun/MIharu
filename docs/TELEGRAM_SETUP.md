# Уведомления Disk Diagnostic

## Production / multi-user mode

Рекомендуемый режим — `backend`. Пользовательский клиент не хранит общий Telegram Bot Token.

Переменная окружения:

```powershell
$env:DISK_DIAGNOSTIC_BACKEND_URL="https://your-backend.example"
$env:DISK_DIAGNOSTIC_NOTIFICATION_MODE="backend"
```

Backend endpoint:

```text
POST /api/v1/notifications/events
Content-Type: application/json
Authorization: Bearer <optional-enrollment-token>
```

Тело события:

```json
{
  "schema_version": 1,
  "installation_id": "per-installation-random-id",
  "event_type": "security_alert",
  "message": "HTML alert message",
  "platform": "windows",
  "hostname": "PC-NAME"
}
```

Общий Telegram Bot Token находится только на сервере. Сервер связывает `installation_id` с Telegram пользователя и отправляет уведомление.

## Direct mode

Только для разработки или self-hosted установки:

```powershell
$env:DISK_DIAGNOSTIC_NOTIFICATION_MODE="direct"
$env:TELEGRAM_BOT_TOKEN="..."
$env:TELEGRAM_CHAT_ID="..."
```

В обычной установке этот режим не используется.

## Off

```powershell
$env:DISK_DIAGNOSTIC_NOTIFICATION_MODE="off"
```

Сканирование и локальная история продолжат работать.

## Хранение данных

Пользовательские данные больше не пишутся на Desktop по умолчанию. Они находятся в:

```text
%LOCALAPPDATA%\DiskDiagnostic\
```

Структура:

```text
Config\
Reports\
History\
Snapshots\
Cache\
Logs\
Alerts\
```

Идентификатор установки — случайный локальный ID, не основанный на имени пользователя, email или hostname.
