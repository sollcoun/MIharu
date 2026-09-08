# Miharu (見張る)

**See what changed. Understand what matters.**

Локальный Windows Security Monitor для рабочих станций и офисов.  
Miharu делает снимок состояния системы, сравнивает его с прошлым сканом, оценивает риски и объясняет, *почему* объект выглядит подозрительно — без обязательного облака и без передачи сырых дампов наружу.

<!--
  ═══════════════════════════════════════════════════════════
  ФОТО 1 — Главное окно
  Файл:  assets/screenshots/01_main_window.png
  Снять: окно Miharu (шапка, статус, QUICK/FULL, TELEGRAM, MONITOR, лог)
  После добавления файла — раскомментировать строку ниже
-->
<!-- ![Miharu — главное окно](assets/screenshots/01_main_window.png) -->

---

## Зачем это нужно

| Проблема | Как помогает Miharu |
|----------|---------------------|
| «Что изменилось на ПК с прошлой проверки?» | Diff снимков: процессы, автозагрузка, службы, задачи, файлы |
| «Это вредонос или легитимный софт?» | Risk Engine: LOW / MEDIUM / HIGH + evidence |
| «Что за процесс SearchHost / WebView2?» | Описания известных процессов на русском + полный список |
| «Нужны алерты без постоянного сидения в UI» | Telegram + фоновый Monitor (Task Scheduler) |
| «Данные не должны уходить в чужой SaaS» | Всё локально: `%LOCALAPPDATA%\DiskDiagnostic` |

---

## Возможности

- **Quick / Full скан** — быстрая или полная проверка дисков и поверхности безопасности Windows
- **Снимки и сравнение** — изменения с прошлого скана (процессы, autorun, services, tasks, files)
- **Risk Engine** — scoring по подписям, путям, издателям, parent-цепочкам, именам
- **Пояснения** — почему выставлен score; опционально AI-текст (Mistral / NVIDIA)
- **Процессы** — полный список новых процессов с описанием «что это» и process tree
- **Хеши + VirusTotal** — опционально (`vt_api_key`)
- **HTML-дашборд** — отчёт в браузере: статус, диски, changes, findings, trees
- **Telegram** — привязка чата одной кнопкой; алерты HIGH / новая persistence
- **Фоновый Monitor** — периодический Quick через планировщик задач

<!--
  ═══════════════════════════════════════════════════════════
  ФОТО 2 — HTML-дашборд
  Файл:  assets/screenshots/02_dashboard.png
  Снять: SYSTEM SECURITY STATUS, gauges Health / Risk / Storage
-->
<!-- ![Дашборд — статус системы](assets/screenshots/02_dashboard.png) -->

<!--
  ═══════════════════════════════════════════════════════════
  ФОТО 3 — Новые процессы с описаниями
  Файл:  assets/screenshots/03_processes.png
  Снять: блок «НОВЫЕ ПРОЦЕССЫ» (имя + пояснение на русском)
-->
<!-- ![Новые процессы с описаниями](assets/screenshots/03_processes.png) -->

<!--
  ═══════════════════════════════════════════════════════════
  ФОТО 4 — HTML-отчёт
  Файл:  assets/screenshots/04_report.png
  Снять: страница «MIHARU — ОТЧЁТ», блок пояснения
-->
<!-- ![HTML-отчёт](assets/screenshots/04_report.png) -->

---

## Для пользователей

Python на целевом ПК **не требуется**.

### Установка

1. Запустите `release\Miharu-Setup-1.1.0.exe`
2. Следуйте мастеру (нужны права администратора)
3. Запуск: меню «Пуск» → **Miharu**

| Что | Путь |
|-----|------|
| Программа | `C:\Program Files\Miharu` |
| Отчёты, настройки, логи, снимки | `%LOCALAPPDATA%\DiskDiagnostic` |

Подробное руководство: **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**

### Первые шаги

1. **Quick** или **Full** — выполнить скан  
2. **Dashboard** — открыть HTML-отчёт  
3. **TELEGRAM** — открыть бота → нажать **Start** (chat_id сохранится сам)  
4. **MONITOR** — включить фоновые проверки по расписанию  

Токен бота в офисной сборке уже внутри установщика.  
На каждом ПК привязывается только **чат** (личный или группа).

<!--
  ═══════════════════════════════════════════════════════════
  ФОТО 5 — Telegram
  Файл:  assets/screenshots/05_telegram_linked.png
  Снять: диалог «Чат успешно привязан»
-->
<!-- ![Telegram — чат привязан](assets/screenshots/05_telegram_linked.png) -->

---

## Для разработчиков

### Требования

| Компонент | Версия |
|-----------|--------|
| ОС | Windows 10 / 11 x64 |
| Python | 3.10+ |
| Зависимости | `PySide6>=6.8,<7` (`requirements.txt`) |
| Установщик | [Inno Setup 6](https://jrsoftware.org/isinfo.php) |

### Запуск из исходников

```powershell
cd C:\path\to\disk_diagnostic-main
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# токен Telegram для dev (один раз)
copy secrets\product_defaults.example.json secrets\product_defaults.json

python run.py
```

Фоновый цикл вручную:

```powershell
python run.py --monitor
```

### Как подхватывается Telegram-токен

Порядок (первый найденный выигрывает):

1. Переменные окружения `TELEGRAM_BOT_TOKEN` / `TELEGRAM_TOKEN`
2. `%LOCALAPPDATA%\DiskDiagnostic\Config\settings.json` → `telegram_bot_token`
3. `secrets/product_defaults.json`
4. `secrets/product_defaults.example.json` (fallback для разработки)

При старте `seed_product_defaults()` копирует токен из product_defaults в `settings.json` и при необходимости включает `notification_mode: "direct"`.  
**chat_id никогда не прописывается автоматически** — только кнопка **TELEGRAM** на конкретной машине.

### Сборка EXE и установщика

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build\build.ps1 -Clean
```

Скрипт:

1. Поднимает изолированный venv в `build\.venv`
2. Ставит PyInstaller и зависимости
3. Готовит `secrets\product_defaults.json` (из env или из example)
4. Собирает onedir-бандл → `dist\Miharu\Miharu.exe`
5. Если найден Inno Setup 6 → `release\Miharu-Setup-1.1.0.exe`

Только EXE, без Setup:

```powershell
.\build\build.ps1 -Clean -SkipInstaller
```

Иконка (multi-size `.ico`):

```powershell
pip install pillow
python .\build\make_icon.py
```

Документация по сборке: **[build/BUILD.md](build/BUILD.md)**

---

## Структура репозитория

```text
run.py                      точка входа GUI / --monitor
run_monitor.py              отдельный entry для планировщика
config.py                   пути, settings, product_defaults
requirements.txt            PySide6

core/
  risk_engine.py            scoring, evidence, top findings
  snapshot.py               снимки и diff
  process_tree.py           parent → child chains
  monitor.py                Task Scheduler, smart mode
  hash_vt.py                хеши, VirusTotal
  ai_explain.py             AI-пояснения
  export_report.py          text / HTML export
  allowlist.py              белые списки
  app_log.py                логирование

ui/
  main_window.py            оболочка, TELEGRAM, MONITOR, скан
  dashboard.py              генерация HTML-дашборда
  scan_worker.py            фоновый worker скана

notifications/
  telegram_alerts.py        direct Telegram + привязка chat_id
  backend_notifications.py  контракт центрального backend
  notifications.py          общий интерфейс провайдеров

scripts/
  disk_diagnostic.ps1       сбор фактов Windows (WMI, подписи, …)

secrets/
  product_defaults.example.json   шаблон (можно коммитить)
  product_defaults.json           боевой токен (НЕ коммитить)
  README.txt

assets/                     логотип, wizard Inno Setup
build/
  build.ps1                 сборка
  Miharu.spec               PyInstaller
  installer.iss             Inno Setup 6
  make_icon.py
  BUILD.md

docs/
  USER_GUIDE.md
  TELEGRAM_SETUP.md
  BACKEND_API.md
```

---

## Настройки

Файл: `%LOCALAPPDATA%\DiskDiagnostic\Config\settings.json`

| Ключ | Описание |
|------|----------|
| `notification_mode` | `off` · `direct` · `backend` |
| `telegram_bot_token` | токен бота (один на команду / офис) |
| `telegram_chat_id` | chat пользователя или группы |
| `selected_drives` | например `["C:", "D:"]` |
| `monitor_enabled` | фоновый монитор |
| `monitor_interval_hours` | интервал (часы) |
| `monitor_mode` | обычно `Quick` |
| `monitor_smart` | Full только при триггере |
| `vt_api_key` | VirusTotal (или env `VT_API_KEY`) |
| `mistral_api_key` / `nvidia_api_key` | AI (опционально) |

Офисная модель: **один бот**, у каждого ПК свой `chat_id` (или общая группа).  
См. [docs/TELEGRAM_SETUP.md](docs/TELEGRAM_SETUP.md) и [docs/BACKEND_API.md](docs/BACKEND_API.md).

---

## Безопасность

- Risk Engine и снимки выполняются **локально**
- AI не назначает уровень угрозы — только формулирует пояснение
- В git не попадают `secrets/product_defaults.json`, `.env`, `dist/`, `release/`
- HTML-отчёт для передачи **не содержит** bot token и полных сырых dumps
- Для multi-user production предпочтителен режим `backend` (токен остаётся на сервере)

---

## Версия и статус

| | |
|--|--|
| Версия | **1.1.0** |
| Назначение | Внутренний / офисный инструмент |
| Лицензия | Внутреннее использование |

---

## Чеклист скриншотов

Создайте папку `assets/screenshots/` и положите туда файлы.  
После этого в `README.md` раскомментируйте соответствующие строки `![…](…)`.

| # | Файл | Что снять |
|---|------|-----------|
| 1 | `01_main_window.png` | Главное окно Miharu |
| 2 | `02_dashboard.png` | Дашборд PROTECTED / gauges |
| 3 | `03_processes.png` | Новые процессы с описаниями |
| 4 | `04_report.png` | HTML-отчёт / пояснение |
| 5 | `05_telegram_linked.png` | Диалог «Чат успешно привязан» |
