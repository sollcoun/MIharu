# Руководство пользователя для Miharu

## Введение

Miharu — это локальный Windows Security Monitor, который предоставляет детальные сведения о состоянии безопасности вашей системы. Он захватывает снимки вашей системы, сравнивает их со временем и оценивает потенциальные риски, предлагая объяснения и действенные рекомендации.

![Miharu Dashboard](https://github.com/yourusername/miharu/blob/main/assets/dashboard.png)

## Установка

### Требования

- Windows 10/11 x64
- Python 3.10+ (не требуется на целевом компьютере)

### Установка

1. Скачайте установщик Miharu-Setup-1.1.0.exe из [релиза](https://github.com/yourusername/miharu/releases).
2. Запустите установщик и следуйте инструкциям.
3. После установки Miharu будет доступен в меню "Пуск".

![Установка](https://github.com/yourusername/miharu/blob/main/assets/installation.png)

## Основные функции

### Быстрые / Полные сканирования дисков

Выполняйте быстрые или полные сканирования ваших дисков и поверхности безопасности.

![Сканирование дисков](https://github.com/yourusername/miharu/blob/main/assets/disk_scan.png)

### Снимки и сравнение

Захватывайте снимки вашей системы и сравнивайте их, чтобы выявить изменения.

![Снимки и сравнение](https://github.com/yourusername/miharu/blob/main/assets/snapshot_diff.png)

### Движок рисков

Оценивайте доказательства и присваивайте оценки рисков (НИЗКИЙ / СРЕДНИЙ / ВЫСОКИЙ).

![Движок рисков](https://github.com/yourusername/miharu/blob/main/assets/risk_engine.png)

### Объяснение

Понимайте, почему была назначена определенная оценка риска.

![Объяснение](https://github.com/yourusername/miharu/blob/main/assets/explain.png)

### Дерево процессов

Просматривайте цепочку родительских и дочерних процессов.

![Дерево процессов](https://github.com/yourusername/miharu/blob/main/assets/process_tree.png)

### Хеши + VirusTotal

Проверяйте хеши файлов через VirusTotal (опционально, требуется API-ключ).

![VirusTotal](https://github.com/yourusername/miharu/blob/main/assets/virustotal.png)

### AI-объяснение

Получайте AI-сгенерированные объяснения для рисков (Mistral/NVIDIA).

![AI-объяснение](https://github.com/yourusername/miharu/blob/main/assets/ai_explanation.png)

### HTML-дашборд

Просматривайте детальные отчеты в HTML-дашборде.

![HTML-дашборд](https://github.com/yourusername/miharu/blob/main/assets/html_dashboard.png)

### Telegram-уведомления

Получайте уведомления о высоких рисках и новых техниках устойчивости.

![Telegram-уведомления](https://github.com/yourusername/miharu/blob/main/assets/telegram_alerts.png)

### Фоновый монитор

Запускайте сканирования в фоновом режиме с помощью планировщика задач.

![Фоновый монитор](https://github.com/yourusername/miharu/blob/main/assets/background_monitor.png)

## Настройки

### Файл настроек

Файл настроек находится по пути: `%LOCALAPPDATA%\DiskDiagnostic\Config\settings.json`

| Ключ | Описание |
|------|----------|
| `notification_mode` | `off` / `direct` / `backend` |
| `telegram_bot_token` | токен бота (один на команду) |
| `telegram_chat_id` | личный или групповой chat id |
| `selected_drives` | например `["C:"]` |
| `monitor_enabled` | фоновый монитор |
| `monitor_interval_hours` | интервал (часы) |
| `monitor_smart` | Quick → Full только при триггере |
| `vt_api_key` / env `VT_API_KEY` | VirusTotal (опционально) |

### Настройка Telegram

1. В приложении нажмите кнопку **TELEGRAM**.
2. Начните чат с ботом, нажав кнопку **Start**.
3. Ваш chat id будет автоматически подтянут.

![Настройка Telegram](https://github.com/yourusername/miharu/blob/main/assets/telegram_setup.png)

## Устранение неполадок

### Общие проблемы

- **Проблема**: Miharu не запускается.
  **Решение**: Убедитесь, что у вас установлена последняя версия Windows и Python 3.10+.

- **Проблема**: Сканирование не завершается.
  **Решение**: Проверьте, не заблокированы ли процессы антивирусом. Попробуйте запустить сканирование вручную.

- **Проблема**: Telegram-уведомления не приходят.
  **Решение**: Убедитесь, что вы правильно настроили токен бота и chat id. Проверьте, не заблокированы ли уведомления в Telegram.

### Контакты поддержки

Если у вас возникли проблемы, пожалуйста, свяжитесь с нами по адресу support@miharu.com или через наш [Telegram-бот](https://t.me/miharu_support_bot).

## Заключение

Miharu — это мощный инструмент для мониторинга безопасности вашей системы. Следуя этому руководству, вы сможете эффективно использовать все его функции и обеспечить безопасность вашего ПК.

![Miharu](https://github.com/yourusername/miharu/blob/main/assets/logo.png)