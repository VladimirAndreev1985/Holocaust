"""Internationalization — English / Russian UI translations."""

from __future__ import annotations

_current_language = "en"

TRANSLATIONS: dict[str, dict[str, str]] = {
    # ============================================================
    #  Main Window
    # ============================================================
    "Holocaust — Network Auditor": {
        "ru": "Holocaust — Сетевой аудитор",
    },
    "Holocaust Network Auditor starting...": {
        "ru": "Запуск Holocaust Network Auditor...",
    },
    "Targets": {
        "ru": "Цели",
    },
    "Dashboard": {
        "ru": "Обзор",
    },
    "Interfaces & Wi-Fi": {
        "ru": "Интерфейсы и Wi-Fi",
    },
    "LAN Scanner": {
        "ru": "Сканер LAN",
    },
    "Vulnerabilities": {
        "ru": "Уязвимости",
    },
    "Metasploit": {
        "ru": "Metasploit",
    },
    "Reports": {
        "ru": "Отчёты",
    },
    "Settings": {
        "ru": "Настройки",
    },
    "Ready": {
        "ru": "Готов",
    },
    "Hosts: 0": {
        "ru": "Хосты: 0",
    },
    "Vulns: 0": {
        "ru": "Уязв.: 0",
    },
    "MSF: disconnected": {
        "ru": "MSF: отключён",
    },
    "MSF: connected": {
        "ru": "MSF: подключён",
    },
    "Scan Running": {
        "ru": "Сканирование запущено",
    },
    "A scan is already in progress.": {
        "ru": "Сканирование уже выполняется.",
    },
    "Scan complete": {
        "ru": "Сканирование завершено",
    },
    "Scan Error": {
        "ru": "Ошибка сканирования",
    },
    "A vulnerability scan is in progress.": {
        "ru": "Сканирование уязвимостей выполняется.",
    },
    "Vulnerability scan complete": {
        "ru": "Сканирование уязвимостей завершено",
    },
    "Failed to connect to msfrpcd.": {
        "ru": "Не удалось подключиться к msfrpcd.",
    },
    "Connect to Metasploit first (Metasploit tab).": {
        "ru": "Сначала подключитесь к Metasploit (вкладка Metasploit).",
    },
    "Exploit Failed": {
        "ru": "Эксплойт не выполнен",
    },
    "Exploit Launched": {
        "ru": "Эксплойт запущен",
    },
    "Updating databases...": {
        "ru": "Обновление баз данных...",
    },

    # ============================================================
    #  Dashboard Tab
    # ============================================================
    "Network Dashboard": {
        "ru": "Панель управления сетью",
    },
    "Select network interface...": {
        "ru": "Выберите сетевой интерфейс...",
    },
    "Target: 192.168.1.0/24": {
        "ru": "Цель: 192.168.1.0/24",
    },
    "Full Network Audit": {
        "ru": "Полный аудит сети",
    },
    "Scanning...": {
        "ru": "Сканирование...",
    },
    "Hosts Found": {
        "ru": "Обнаружено хостов",
    },
    "IP Cameras": {
        "ru": "IP-камеры",
    },
    "PCs / Servers": {
        "ru": "ПК / Серверы",
    },
    "Critical": {
        "ru": "Критические",
    },

    # tooltip
    "Scan target — auto-detected from interface.\n"
    "Edit manually to scan custom range.\n"
    "Examples: 192.168.1.0/24, 10.0.0.1-50, 172.16.0.0/16": {
        "ru": "Цель сканирования — определена автоматически.\n"
              "Измените вручную для другого диапазона.\n"
              "Примеры: 192.168.1.0/24, 10.0.0.1-50, 172.16.0.0/16",
    },

    # ============================================================
    #  LAN Tab
    # ============================================================
    "Scan Network": {
        "ru": "Сканировать сеть",
    },
    "Vuln Scan Selected": {
        "ru": "Скан уязвимостей",
    },
    "Filter:": {
        "ru": "Фильтр:",
    },
    "All Devices": {
        "ru": "Все устройства",
    },
    "Cameras": {
        "ru": "Камеры",
    },
    "PCs (Windows)": {
        "ru": "ПК (Windows)",
    },
    "PCs (Linux)": {
        "ru": "ПК (Linux)",
    },
    "PCs (Mac)": {
        "ru": "ПК (Mac)",
    },
    "Servers": {
        "ru": "Серверы",
    },
    "Phones": {
        "ru": "Телефоны",
    },
    "Routers": {
        "ru": "Маршрутизаторы",
    },
    "IoT": {
        "ru": "IoT",
    },
    "Printers": {
        "ru": "Принтеры",
    },
    "Unknown": {
        "ru": "Неизвестные",
    },
    "Search by IP, hostname, vendor...": {
        "ru": "Поиск по IP, имени хоста, вендору...",
    },
    "High Risk Only": {
        "ru": "Только высокий риск",
    },
    "0 devices": {
        "ru": "0 устройств",
    },
    "IP Address": {
        "ru": "IP-адрес",
    },
    "Hostname": {
        "ru": "Имя хоста",
    },
    "MAC": {
        "ru": "MAC",
    },
    "Vendor": {
        "ru": "Вендор",
    },
    "Type": {
        "ru": "Тип",
    },
    "OS": {
        "ru": "ОС",
    },
    "Ports": {
        "ru": "Порты",
    },
    "Vulns": {
        "ru": "Уязв.",
    },
    "Risk": {
        "ru": "Риск",
    },

    # ============================================================
    #  Vulnerabilities Tab
    # ============================================================
    "Vulnerabilities & Exploits": {
        "ru": "Уязвимости и эксплойты",
    },
    "0 vulnerabilities": {
        "ru": "0 уязвимостей",
    },
    "All Severities": {
        "ru": "Все уровни",
    },
    "High": {
        "ru": "Высокий",
    },
    "Medium": {
        "ru": "Средний",
    },
    "Low": {
        "ru": "Низкий",
    },
    "Info": {
        "ru": "Инфо",
    },
    "Severity:": {
        "ru": "Уровень:",
    },
    "Search CVE, title, host...": {
        "ru": "Поиск по CVE, названию, хосту...",
    },
    "Exploitable Only": {
        "ru": "Только эксплуатируемые",
    },
    "CVE": {
        "ru": "CVE",
    },
    "Title": {
        "ru": "Название",
    },
    "Host": {
        "ru": "Хост",
    },
    "Port": {
        "ru": "Порт",
    },
    "CVSS": {
        "ru": "CVSS",
    },
    "Severity": {
        "ru": "Уровень",
    },
    "Exploitable": {
        "ru": "Эксплуатируемый",
    },
    "Action": {
        "ru": "Действие",
    },
    "Vulnerability Details": {
        "ru": "Подробности уязвимости",
    },
    "Launch Best Exploit": {
        "ru": "Запустить лучший эксплойт",
    },
    "Copy CVE": {
        "ru": "Копировать CVE",
    },
    "Exploit": {
        "ru": "Эксплойт",
    },
    "Confirm Exploit": {
        "ru": "Подтверждение эксплойта",
    },
    "YES": {
        "ru": "ДА",
    },
    "Yes": {
        "ru": "Да",
    },
    "No": {
        "ru": "Нет",
    },
    "N/A": {
        "ru": "Н/Д",
    },
    "Description": {
        "ru": "Описание",
    },
    "Source:": {
        "ru": "Источник:",
    },
    "Confirmed:": {
        "ru": "Подтверждено:",
    },
    "Available Exploits:": {
        "ru": "Доступные эксплойты:",
    },
    "References:": {
        "ru": "Ссылки:",
    },

    # ============================================================
    #  Metasploit Tab
    # ============================================================
    "Metasploit Framework": {
        "ru": "Metasploit Framework",
    },
    "Disconnected": {
        "ru": "Отключён",
    },
    "Connected": {
        "ru": "Подключён",
    },
    "Connect to msfrpcd": {
        "ru": "Подключиться к msfrpcd",
    },
    "Disconnect": {
        "ru": "Отключиться",
    },
    "Host:": {
        "ru": "Хост:",
    },
    "Port:": {
        "ru": "Порт:",
    },
    "Password:": {
        "ru": "Пароль:",
    },
    "Module Search": {
        "ru": "Поиск модулей",
    },
    "Search modules (e.g. 'eternalblue', 'CVE-2021-36260')...": {
        "ru": "Поиск модулей (напр. 'eternalblue', 'CVE-2021-36260')...",
    },
    "Search": {
        "ru": "Поиск",
    },
    "Module": {
        "ru": "Модуль",
    },
    "Rank": {
        "ru": "Ранг",
    },
    "Exploit Configuration": {
        "ru": "Настройка эксплойта",
    },
    "Module:": {
        "ru": "Модуль:",
    },
    "RHOSTS:": {
        "ru": "RHOSTS:",
    },
    "Target IP": {
        "ru": "IP цели",
    },
    "RPORT:": {
        "ru": "RPORT:",
    },
    "Payload:": {
        "ru": "Полезная нагрузка:",
    },
    "Run Exploit": {
        "ru": "Запустить эксплойт",
    },
    "Active Sessions": {
        "ru": "Активные сессии",
    },
    "Refresh Sessions": {
        "ru": "Обновить сессии",
    },
    "ID": {
        "ru": "ID",
    },
    "Target": {
        "ru": "Цель",
    },
    "Platform": {
        "ru": "Платформа",
    },
    "Use": {
        "ru": "Выбрать",
    },
    "Missing Fields": {
        "ru": "Незаполненные поля",
    },
    "Module and target IP are required.": {
        "ru": "Необходимо указать модуль и IP цели.",
    },
    "Confirm Exploit Execution": {
        "ru": "Подтверждение запуска эксплойта",
    },

    # ============================================================
    #  Interfaces Tab
    # ============================================================
    "Network Interfaces & Wi-Fi": {
        "ru": "Сетевые интерфейсы и Wi-Fi",
    },
    "Network Adapters": {
        "ru": "Сетевые адаптеры",
    },
    "Refresh": {
        "ru": "Обновить",
    },
    "Up": {
        "ru": "Включить",
    },
    "Down": {
        "ru": "Выключить",
    },
    "Monitor Mode": {
        "ru": "Режим мониторинга",
    },
    "Managed Mode": {
        "ru": "Управляемый режим",
    },
    "Check Kill": {
        "ru": "Check Kill",
    },
    "Name": {
        "ru": "Имя",
    },
    "Status": {
        "ru": "Статус",
    },
    "Mode": {
        "ru": "Режим",
    },
    "SSID": {
        "ru": "SSID",
    },
    "Gateway": {
        "ru": "Шлюз",
    },
    "Wi-Fi Networks": {
        "ru": "Сети Wi-Fi",
    },
    "Scan Wi-Fi": {
        "ru": "Сканировать Wi-Fi",
    },
    "Connect": {
        "ru": "Подключиться",
    },
    "Password (leave empty for open)": {
        "ru": "Пароль (оставьте пустым для открытых)",
    },
    "BSSID": {
        "ru": "BSSID",
    },
    "Channel": {
        "ru": "Канал",
    },
    "Signal": {
        "ru": "Сигнал",
    },
    "Encryption": {
        "ru": "Шифрование",
    },
    "Cipher": {
        "ru": "Шифр",
    },
    "Clients": {
        "ru": "Клиенты",
    },
    "OPEN": {
        "ru": "ОТКРЫТ",
    },
    "<hidden>": {
        "ru": "<скрыт>",
    },

    # ============================================================
    #  Reports Tab
    # ============================================================
    "Generate Report": {
        "ru": "Генерация отчёта",
    },
    "Generate HTML Report": {
        "ru": "Сгенерировать HTML-отчёт",
    },
    "Generate PDF Report": {
        "ru": "Сгенерировать PDF-отчёт",
    },
    "Open Report Folder": {
        "ru": "Открыть папку отчётов",
    },
    "Report Preview": {
        "ru": "Предпросмотр отчёта",
    },

    # ============================================================
    #  Settings Tab
    # ============================================================
    "Database Status": {
        "ru": "Состояние баз данных",
    },
    "Component": {
        "ru": "Компонент",
    },
    "Details": {
        "ru": "Подробности",
    },
    "Last Updated": {
        "ru": "Обновлено",
    },
    "Nmap Scripts": {
        "ru": "Скрипты Nmap",
    },
    "Metasploit DB": {
        "ru": "БД Metasploit",
    },
    "CVE Cache": {
        "ru": "Кэш CVE",
    },
    "Device Signatures": {
        "ru": "Сигнатуры устройств",
    },
    "Vulners API": {
        "ru": "Vulners API",
    },
    "Refresh Status": {
        "ru": "Обновить статус",
    },
    "General": {
        "ru": "Общие",
    },
    "Log Level:": {
        "ru": "Уровень логов:",
    },
    "Auto-update databases on startup": {
        "ru": "Обновлять базы данных при запуске",
    },
    "Confirm before running exploits": {
        "ru": "Подтверждение перед запуском эксплойтов",
    },
    "Scanning": {
        "ru": "Сканирование",
    },
    "Scan Timeout:": {
        "ru": "Таймаут сканирования:",
    },
    "Port Range:": {
        "ru": "Диапазон портов:",
    },
    "Scan Speed:": {
        "ru": "Скорость сканирования:",
    },
    "T1 (Sneaky)": {
        "ru": "T1 (Скрытный)",
    },
    "T2 (Polite)": {
        "ru": "T2 (Вежливый)",
    },
    "T3 (Normal)": {
        "ru": "T3 (Обычный)",
    },
    "T4 (Aggressive)": {
        "ru": "T4 (Агрессивный)",
    },
    "T5 (Insane)": {
        "ru": "T5 (Безумный)",
    },
    "RPC Host:": {
        "ru": "RPC-хост:",
    },
    "RPC Port:": {
        "ru": "RPC-порт:",
    },
    "RPC Password:": {
        "ru": "RPC-пароль:",
    },
    "Auto-connect to Metasploit on startup": {
        "ru": "Автоподключение к Metasploit при запуске",
    },
    "API Key:": {
        "ru": "API-ключ:",
    },
    "API key (optional)": {
        "ru": "API-ключ (необязательно)",
    },
    "Paths": {
        "ru": "Пути",
    },
    "Log Directory:": {
        "ru": "Каталог логов:",
    },
    "Report Directory:": {
        "ru": "Каталог отчётов:",
    },
    "Save Settings": {
        "ru": "Сохранить настройки",
    },
    "Update All Databases": {
        "ru": "Обновить все базы данных",
    },
    "Settings saved successfully.": {
        "ru": "Настройки сохранены.",
    },
    "Language": {
        "ru": "Язык",
    },
    "Language:": {
        "ru": "Язык:",
    },
    "Installed": {
        "ru": "Установлен",
    },
    "Not found": {
        "ru": "Не найден",
    },
    "Active": {
        "ru": "Активна",
    },
    "Empty": {
        "ru": "Пуста",
    },
    "0 entries — run Update All": {
        "ru": "0 записей — запустите обновление",
    },
    "Error": {
        "ru": "Ошибка",
    },
    "Not created": {
        "ru": "Не создана",
    },
    "Will be created on first run": {
        "ru": "Будет создана при первом запуске",
    },
    "Configured": {
        "ru": "Настроен",
    },
    "Key set": {
        "ru": "Ключ задан",
    },
    "No API key": {
        "ru": "Нет API-ключа",
    },
    "Optional — works without key (limited)": {
        "ru": "Необязательно — работает без ключа (ограниченно)",
    },
    "Use 'Update All'": {
        "ru": "Используйте «Обновить все»",
    },

    # ============================================================
    #  Detail Panel
    # ============================================================
    "Device Details": {
        "ru": "Информация об устройстве",
    },
    "Overview": {
        "ru": "Обзор",
    },
    "Services": {
        "ru": "Сервисы",
    },
    "Notes": {
        "ru": "Заметки",
    },
    "Notes about this device...": {
        "ru": "Заметки об устройстве...",
    },
    "IP Address:": {
        "ru": "IP-адрес:",
    },
    "MAC Address:": {
        "ru": "MAC-адрес:",
    },
    "Hostname:": {
        "ru": "Имя хоста:",
    },
    "Vendor:": {
        "ru": "Вендор:",
    },
    "Device Type:": {
        "ru": "Тип устройства:",
    },
    "OS:": {
        "ru": "ОС:",
    },
    "Open Ports:": {
        "ru": "Открытые порты:",
    },
    "Risk Level:": {
        "ru": "Уровень риска:",
    },
    "Vulnerabilities:": {
        "ru": "Уязвимости:",
    },
    "Camera Model:": {
        "ru": "Модель камеры:",
    },
    "Protocol": {
        "ru": "Протокол",
    },
    "Service": {
        "ru": "Сервис",
    },
    "Product": {
        "ru": "Продукт",
    },
    "Version": {
        "ru": "Версия",
    },

    # ============================================================
    #  Log Panel
    # ============================================================
    "Logs": {
        "ru": "Логи",
    },
    "Logs +": {
        "ru": "Логи +",
    },
    "ALL": {
        "ru": "ВСЕ",
    },
    "Clear": {
        "ru": "Очистить",
    },
    "0 lines": {
        "ru": "0 строк",
    },

    # ============================================================
    #  Report Generator HTML
    # ============================================================
    "Holocaust — Network Audit Report": {
        "ru": "Holocaust — Отчёт сетевого аудита",
    },
    "Devices Found": {
        "ru": "Обнаружено устройств",
    },
    "Critical Vulns": {
        "ru": "Критические уязв.",
    },
    "Discovered Devices": {
        "ru": "Обнаруженные устройства",
    },
    "Open Ports": {
        "ru": "Открытые порты",
    },
    "Holocaust Network Auditor — Report generated automatically": {
        "ru": "Holocaust Network Auditor — Отчёт сгенерирован автоматически",
    },
    "Generated:": {
        "ru": "Сгенерирован:",
    },
    "Target:": {
        "ru": "Цель:",
    },
    "Scan duration:": {
        "ru": "Длительность сканирования:",
    },

    # ============================================================
    #  Dynamic format strings (used with .format or f-strings)
    # ============================================================
    "{count} devices": {
        "ru": "{count} устройств",
    },
    "{count} vulnerabilities": {
        "ru": "{count} уязвимостей",
    },
    "{count} lines": {
        "ru": "{count} строк",
    },
    "Scanning {target}...": {
        "ru": "Сканирование {target}...",
    },
    "Scan error: {error}": {
        "ru": "Ошибка сканирования: {error}",
    },
    "Selected: {name} ({ip})": {
        "ru": "Выбрано: {name} ({ip})",
    },
    "Hosts: {count}": {
        "ru": "Хосты: {count}",
    },
    "Vulns: {count}": {
        "ru": "Уязв.: {count}",
    },
    "Report saved: {path}": {
        "ru": "Отчёт сохранён: {path}",
    },
    "Report generated at: {path}": {
        "ru": "Отчёт сгенерирован: {path}",
    },
    "Device: {name}": {
        "ru": "Устройство: {name}",
    },
    "Updates done: {ok}/{total} successful": {
        "ru": "Обновление завершено: {ok}/{total} успешно",
    },
    "Run {module} against {target}?": {
        "ru": "Запустить {module} против {target}?",
    },
    "{count} CVE entries cached": {
        "ru": "{count} CVE-записей в кэше",
    },
    "Scan finished: {count} devices found": {
        "ru": "Сканирование завершено: найдено {count} устройств",
    },
    "Starting full network scan on {target}": {
        "ru": "Запуск полного сканирования сети {target}",
    },
    "Starting vuln scan on {count} devices": {
        "ru": "Запуск сканирования уязвимостей для {count} устройств",
    },
    "Risk: {level}": {
        "ru": "Риск: {level}",
    },
    "{ports} ports": {
        "ru": "{ports} портов",
    },
    "({count} vulns)": {
        "ru": "({count} уязв.)",
    },

    # ============================================================
    #  Scan Depth & Automation
    # ============================================================
    "Quick Scan": {
        "ru": "Быстрое сканирование",
    },
    "Standard Scan": {
        "ru": "Стандартное сканирование",
    },
    "Deep Scan": {
        "ru": "Глубокое сканирование",
    },
    "Start Quick Scan": {
        "ru": "Быстрое сканирование",
    },
    "Start Standard Scan": {
        "ru": "Стандартное сканирование",
    },
    "Start Deep Scan": {
        "ru": "Глубокое сканирование",
    },
    "Start Scan": {
        "ru": "Начать сканирование",
    },
    "Quick — top 100 ports, fast detection\n"
    "Standard — configured port range, OS detection\n"
    "Deep — all 65535 ports, aggressive audit + auto vuln scan": {
        "ru": "Быстрое — топ 100 портов, быстрое обнаружение\n"
              "Стандартное — настроенный диапазон портов, определение ОС\n"
              "Глубокое — все 65535 портов, агрессивный аудит + авто-скан уязвимостей",
    },
    "Auto vuln scan after discovery": {
        "ru": "Авто-скан уязвимостей после обнаружения",
    },
    "Automatically run vulnerability scan on all discovered hosts\n"
    "after the network scan completes.": {
        "ru": "Автоматически запускать сканирование уязвимостей\n"
              "для всех обнаруженных хостов после завершения сканирования сети.",
    },
    "Auto-generate report": {
        "ru": "Авто-генерация отчёта",
    },
    "Automatically generate HTML report after all scans complete.": {
        "ru": "Автоматически генерировать HTML-отчёт после завершения всех сканирований.",
    },
    "Default Scan Depth:": {
        "ru": "Глубина сканирования:",
    },
    "Quick — top 100 ports": {
        "ru": "Быстрое — топ 100 портов",
    },
    "Standard — configured range": {
        "ru": "Стандартное — настроенный диапазон",
    },
    "Deep — all ports, aggressive": {
        "ru": "Глубокое — все порты, агрессивное",
    },

    # ============================================================
    #  Context Menu & Batch Actions
    # ============================================================
    "Rescan Host": {
        "ru": "Пересканировать хост",
    },
    "Vulnerability Scan": {
        "ru": "Сканирование уязвимостей",
    },
    "Send to Metasploit": {
        "ru": "Отправить в Metasploit",
    },
    "Copy IP": {
        "ru": "Копировать IP",
    },
    "Copy MAC": {
        "ru": "Копировать MAC",
    },
    "View Details": {
        "ru": "Подробности",
    },
    "Remove from Results": {
        "ru": "Удалить из результатов",
    },
    "Select / deselect all": {
        "ru": "Выделить / снять выделение",
    },
    "Scan selected devices": {
        "ru": "Сканировать выбранные устройства",
    },
    "Send selected to Metasploit": {
        "ru": "Отправить выбранные в Metasploit",
    },
    "Remove selected from results": {
        "ru": "Удалить выбранные из результатов",
    },
    "Selected devices": {
        "ru": "Выбранные устройства",
    },
    "All": {
        "ru": "Все",
    },
    "Scan": {
        "ru": "Скан",
    },
    "Del": {
        "ru": "Удл",
    },
    "No Selection": {
        "ru": "Ничего не выбрано",
    },
    "Select devices first (checkboxes in sidebar).": {
        "ru": "Сначала выберите устройства (чекбоксы в боковой панели).",
    },
    "A host scan is already in progress.": {
        "ru": "Сканирование хоста уже выполняется.",
    },
    "Host scan complete": {
        "ru": "Сканирование хостов завершено",
    },
    "Scanning {count} host(s)...": {
        "ru": "Сканирование {count} хост(ов)...",
    },
    "{count} device(s) selected": {
        "ru": "{count} устройств выбрано",
    },
    "Scanning {count}...": {
        "ru": "Сканирование {count}...",
    },
    "Stop": {
        "ru": "Стоп",
    },
    "Scan aborted": {
        "ru": "Сканирование прервано",
    },

    # ============================================================
    #  Restart notice
    # ============================================================
    "Language changed. Restart the application to apply.": {
        "ru": "Язык изменён. Перезапустите приложение для применения.",
    },
    "Language Changed": {
        "ru": "Язык изменён",
    },
}


def set_language(lang: str) -> None:
    """Set current UI language ('en' or 'ru')."""
    global _current_language
    _current_language = lang


def get_language() -> str:
    """Return current language code."""
    return _current_language


def tr(text: str) -> str:
    """Translate a string to current language. Returns original if no translation."""
    if _current_language == "en":
        return text
    entry = TRANSLATIONS.get(text)
    if entry:
        return entry.get(_current_language, text)
    return text
