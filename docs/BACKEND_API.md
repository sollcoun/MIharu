# Notification Backend API — v1

Минимальный контракт центрального сервиса уведомлений для Miharu.

Цель: клиент **не** хранит shared Telegram Bot Token.  
Сервер принимает событие, сопоставляет установку с пользователем и доставляет сообщение в Telegram.

---

## Endpoint

```http
POST /api/v1/notifications/events
Content-Type: application/json
Authorization: Bearer <enrollment-or-short-lived-token>
```

Рекомендуется **только HTTPS** в production.

Базовый URL клиент берёт из:

- env `DISK_DIAGNOSTIC_BACKEND_URL`
- или настройки (если добавлены в продукт)

Режим клиента: `notification_mode = "backend"`.

---

## Authentication

| Требование | |
|------------|--|
| TLS | Обязательно в production |
| Credential | Short-lived token или enrollment на установку |
| Bot token | **Никогда** не отдавать клиенту |

Сервер аутентифицирует `installation_id` (или enrollment token) и только после этого шлёт в Telegram.

---

## Request body

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

| Поле | Обязательно | Описание |
|------|-------------|----------|
| `schema_version` | да | Сейчас `1` |
| `installation_id` | да | Локальный ID установки Miharu |
| `event_type` | да | Например `security_alert` |
| `message` | да | Текст/HTML, уже подготовленный для Telegram |
| `platform` | нет | `windows` |
| `hostname` | нет | Имя ПК (не использовать как идентификатор безопасности) |

Клиент **не** присылает полный JSON-отчёт скана — только готовое сообщение алерта.

---

## Response

Успех:

```json
{
  "ok": true,
  "event_id": "evt_..."
}
```

Ошибка:

```json
{
  "ok": false,
  "error": "human-readable reason"
}
```

Рекомендуемые HTTP-коды: `200` / `201` при успехе, `400` валидация, `401`/`403` auth, `429` rate limit, `5xx` сбой сервера.

---

## Обязанности сервера

1. **Authenticate** installation / enrollment  
2. **Resolve** `installation_id` → user → Telegram `chat_id`  
3. **Rate-limit** алерты на установку и на пользователя  
4. **Deduplicate** повторяющиеся события (тот же hash сообщения / окно времени)  
5. **Send** через server-side Telegram Bot Token  
6. **Audit** статус доставки без хранения сырых отчётов дольше необходимого  
7. **Never** выполнять команды или открывать файлы, пришедшие от клиента  

---

## Рекомендуемая модель данных (сервер)

```text
installations
  installation_id  PK
  enrolled_at
  last_seen_at
  user_id / chat_id
  revoked

alert_events
  event_id
  installation_id
  event_type
  message_hash
  created_at
  delivery_status
```

Точный schema — на усмотрение backend-команды; клиенту достаточно контракта выше.

---

## Клиент Miharu

- Режим `backend` задаётся env или settings  
- При алерте формируется HTML/текст сообщения локально  
- Уходит только event, не bot token и не полный report  

Подробности direct/off: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)

---

## Версия

| | |
|--|--|
| API | **v1** |
| Статус | Контракт для внедрения; backend поставляется отдельно от десктоп-клиента |
