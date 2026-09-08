# Notification Backend API — v1

Это минимальный контракт для будущего центрального сервиса.

## Endpoint

`POST /api/v1/notifications/events`

## Authentication

Для production использовать TLS и short-lived/enrollment credentials. Shared Telegram Bot Token никогда не передавать клиенту.

## Request

```json
{
  "schema_version": 1,
  "installation_id": "32-byte-random-hex",
  "event_type": "security_alert",
  "message": "<telegram-html-alert>",
  "platform": "windows",
  "hostname": "OPTIONAL"
}
```

## Response

Success:

```json
{"ok": true, "event_id": "evt_..."}
```

Error:

```json
{"ok": false, "error": "..."}
```

## Server responsibilities

- authenticate installation;
- resolve installation → user → Telegram chat;
- rate-limit alerts;
- deduplicate repeated events;
- send via the server-side Telegram Bot Token;
- audit delivery status without storing raw reports unnecessarily;
- never execute client-provided commands or files.
