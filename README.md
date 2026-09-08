# Miharu (見張る)

**See what changed. Understand what matters.**

Miharu — это локальный Windows Security Monitor, который предоставляет детальные сведения о состоянии безопасности вашей системы. Он захватывает снимки вашей системы, сравнивает их со временем и оценивает потенциальные риски, предлагая объяснения и действенные рекомендации.

![Miharu Dashboard](https://github.com/yourusername/miharu/blob/main/assets/dashboard.png)

## Возможности

- **Быстрые / Полные сканирования дисков**: Выполняйте быстрые или полные сканирования ваших дисков и поверхности безопасности.
- **Снимки и сравнение**: Захватывайте снимки вашей системы и сравнивайте их, чтобы выявить изменения.
- **Движок рисков**: Оценивайте доказательства и присваивайте оценки рисков (НИЗКИЙ / СРЕДНИЙ / ВЫСОКИЙ).
- **Объяснение**: Понимайте, почему была назначена определенная оценка риска.
- **Дерево процессов**: Просматривайте цепочку родительских и дочерних процессов.
- **Хеши + VirusTotal**: Проверяйте хеши файлов через VirusTotal (опционально, требуется API-ключ).
- **AI-объяснение**: Получайте AI-сгенерированные объяснения для рисков (Mistral/NVIDIA).
- **HTML-дашборд**: Просматривайте детальные отчеты в HTML-дашборде.
- **Telegram-уведомления**: Получайте уведомления о высоких рисках и новых техниках устойчивости.
- **Фоновый монитор**: Запускайте сканирования в фоновом режиме с помощью планировщика задач.

Данные хранятся локально на вашем ПК: `%LOCALAPPDATA%\DiskDiagnostic`

---

## Для пользователей

См. **[USER_GUIDE.md](docs/USER_GUIDE.md)** или установщик:

```text
release\Miharu-Setup-1.1.0.exe
```

Python на целевом компьютере **не нужен**.

| Что | Путь |
|-----|------|
| Программа | `C:\Program Files\Miharu` |
| Отчёты, настройки, логи | `%LOCALAPPDATA%\DiskDiagnostic` |

---

## Для разработчиков

### Требования

- Windows 10/11 x64
- Python 3.10+
- (Сборка Setup) [Inno Setup 6](https://jrsoftware.org/isinfo.php)

### Запуск из исходников

```powershell
cd D:\Projects\disk_diagnostic
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

### Сборка EXE и установщика

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build\build.ps1 -Clean
```

Результат:

```text
dist\Miharu\Miharu.exe
release\Miharu-Setup-1.1.0.exe
```

Только EXE, без Inno:

```powershell
.\build\build.ps1 -Clean -SkipInstaller
```

Иконка (multi-size `.ico`):

```powershell
pip install pillow
python .\build\make_icon.py
```

---

## Структура проекта

```text
config.py              пути, настройки, схема
run.py                 GUI
run_monitor.py         фоновый цикл (Task Scheduler)
core/                  risk, snapshot, hash/VT, AI, monitor, process_tree
ui/                    main_window, dashboard
notifications/         Telegram, backend-заготовка
scripts/               disk_diagnostic.ps1 (сбор фактов)
assets/                логотип, мастер установки
build/                 PyInstaller + Inno
docs/                  документация
```

---

## Настройки

Файл: `%LOCALAPPDATA%\DiskDiagnostic\Config\settings.json`

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

Telegram: В приложении нажмите кнопку **TELEGRAM** → Start у бота (chat id подтянется).

---

## Безопасность

- Сканирование и оценка рисков выполняются **локально**
- AI не задает уровни угроз, только объясняет их
- Не коммитьте токены ботов в git
- Для офиса: один бот, у каждого пользователя свой chat id (или общая группа)

---

## Лицензия / статус

Внутренний / офисный инструмент. Версия продукта: **1.1.0**.
