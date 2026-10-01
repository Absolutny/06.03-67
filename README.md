# 🏋️ Спортивный Комплекс

Веб-приложение для управления спортивным комплексом: каталог услуг, онлайн-запись клиентов, панель тренера, админ-панель, журнал аудита и автоматическое резервное копирование.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 📖 Содержание

- [Возможности](#-возможности)
- [Стек технологий](#-стек-технологий)
- [Быстрый старт](#-быстрый-старт)
- [Роли и учётные записи](#-роли-и-учётные-записи)
- [Структура проекта](#-структура-проекта)
- [Переменные окружения](#-переменные-окружения)
- [Безопасность](#-безопасность)
- [Резервное копирование](#-резервное-копирование)
- [Развёртывание](#-развёртывание)
- [FAQ](#-faq)
- [Лицензия](#-лицензия)

---

## ✨ Возможности

### Общее
- 🔐 Регистрация и вход по логину и паролю (PBKDF2-SHA256, 600 000 итераций)
- 🛡️ CSRF-защита всех форм, строгие HTTP-заголовки (CSP, HSTS, X-Frame-Options и др.)
- 🚦 Rate limiting: попытки входа, регистрация, запись, смена пароля
- ⏱️ Автоматический выход при бездействии (30 мин) и по истечении срока сессии (8 ч)
- 📝 Журнал аудита всех значимых событий безопасности
- 💾 Ежечасное резервное копирование базы данных (SQLite `.backup`, безопасно при работе)

### Клиент
- 📅 Запись на любую услугу с выбором даты (до года вперёд)
- ❌ Отмена собственных записей в любой момент (статусы `pending` и `accepted`)
- 📊 Личный кабинет с фильтром записей по статусу и статистикой
- 👤 Профиль: редактирование ФИО, смена пароля, удаление аккаунта

### Тренер
- ✅ Принятие / отклонение заявок клиентов
- 📋 Просмотр всех заявок с приоритетом новых

### Администратор
- 🆕 Создание, редактирование и удаление услуг
- 👥 Найм тренеров (создание их учётных записей)
- 📜 Просмотр журнала аудита с пагинацией

---

## 🛠 Стек технологий

| Компонент | Технология |
|---|---|
| Язык | Python 3.10+ |
| Веб-фреймворк | Flask 3.1 |
| WSGI-сервер | Werkzeug (dev), gunicorn/waitress (prod) |
| БД | SQLite 3 |
| Фронтенд | Jinja2, Bootstrap 5, Bootstrap Icons (локально) |
| Аутентификация | Flask session + Werkzeug security |
| Зависимости | `Flask`, `Werkzeug` |

---

## 🚀 Быстрый старт

### 1. Клонировать репозиторий

```bash
git clone https://github.com/your-username/sport-complex.git
cd sport-complex
```

### 2. Создать виртуальное окружение (рекомендуется)

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Установить зависимости

```bash
pip install -r requirements.txt
```

### 4. Инициализировать базу данных

**Обычный режим** — создаст 6 услуг и администратора со случайным паролем (пароль выведется в консоль один раз):

```bash
python init_db.py
```

**Режим разработки** — плюс тестовые аккаунты `admin` / `trainer` / `client` с известными паролями:

```bash
python init_db.py --demo
```

### 5. Запустить сервер

```bash
python app.py
```

Открой [http://127.0.0.1:5000](http://127.0.0.1:5000).

### 6. Быстрый запуск на Windows

Дважды кликни `run.bat` — он сам:
1. найдёт Python,
2. поставит зависимости,
3. инициализирует БД с тестовыми данными,
4. откроет браузер,
5. запустит сервер.

---

## 👥 Роли и учётные записи

| Роль | Создаётся | Возможности |
|---|---|---|
| **client** | Самостоятельно через `/register` | Запись, отмена, профиль |
| **trainer** | Админом через `/admin/hire_trainer` | Обработка заявок |
| **admin** | `init_db.py` | Всё выше + услуги, тренеры, аудит |

### Тестовые аккаунты (только `--demo`)

| Логин | Пароль | Роль |
|---|---|---|
| `admin` | `Admin123!` | Администратор |
| `trainer` | `Trainer123!` | Тренер |
| `client` | `Client123!` | Клиент |

> ⚠️ **Никогда не используйте `--demo` в боевом режиме.** Эти пароли публично известны.

---

## 📁 Структура проекта

```
sport-complex/
├── app.py                 # Маршруты и логика приложения
├── config.py              # Конфигурация (SECRET_KEY, БД, сессии)
├── db.py                  # Работа с SQLite (подключение, запросы)
├── security.py            # Пароли, CSRF, RBAC, HTTP-заголовки
├── rate_limit.py          # Ограничение частоты запросов
├── audit.py               # Журнал аудита
├── backup.py              # Автоматическое резервное копирование
├── init_db.py             # Инициализация БД
├── migrate.py             # Одноразовые миграции
├── schema.sql             # Схема БД
├── requirements.txt       # Зависимости Python
├── run.bat                # Быстрый запуск на Windows
├── sport.db               # База данных (создаётся автоматически)
├── instance/
│   └── secret_key         # Постоянный SECRET_KEY (генерируется при первом запуске)
├── backups/               # Резервные копии БД (хранятся последние 48)
├── templates/             # Jinja2-шаблоны
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── change_password.html
│   ├── my_bookings.html
│   ├── add_service.html
│   ├── edit_service.html
│   ├── hire_trainer.html
│   ├── trainer_bookings.html
│   ├── audit_log.html
│   └── error.html
└── static/
    ├── css/style.css
    ├── js/main.js
    └── vendor/
        ├── bootstrap/
        └── bootstrap-icons/
```

---

## ⚙️ Переменные окружения

Все переменные опциональны — при отсутствии используются безопасные значения по умолчанию.

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `SECRET_KEY` | Ключ подписи сессий | Генерируется автоматически в `instance/secret_key` |
| `SPORT_DB` | Путь к файлу БД | `<project>/sport.db` |
| `SPORT_BACKUP_DIR` | Папка для бэкапов | `<project>/backups` |
| `BACKUP_ENABLED` | Включить автобэкапы | `1` |
| `FLASK_DEBUG` | Режим отладки | `0` (выключен) |
| `HOST` | Адрес прослушивания | `127.0.0.1` |
| `PORT` | Порт | `5000` |
| `TRUSTED_PROXY_COUNT` | Кол-во доверенных прокси перед приложением | `0` |
| `SESSION_COOKIE_SECURE` | Только HTTPS-cookie (включить в проде!) | `0` |
| `ADMIN_PASSWORD` | Пароль первого администратора | Случайный |

### Пример (Linux/macOS)

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SESSION_COOKIE_SECURE=1
export HOST=0.0.0.0
export PORT=8080
python app.py
```

### Пример (Windows PowerShell)

```powershell
$env:SECRET_KEY = "your-long-random-string"
$env:SESSION_COOKIE_SECURE = "1"
python app.py
```

---

## 🔒 Безопасность

Приложение следует рекомендациям OWASP и защищено от основных веб-уязвимостей.

| Угроза | Защита |
|---|---|
| **SQL-инъекции** | Только параметризованные запросы через `execute_query` / `execute_commit` |
| **XSS** | Автоэкранирование Jinja2 + строгий CSP без `unsafe-inline` |
| **CSRF** | Одноразовый токен в каждой форме + проверка `Origin`/`Referer` |
| **Brute-force** | Rate limiting по IP (5 попыток / 5 мин) и по логину (10 / 15 мин) |
| **Session fixation** | `session.clear()` перед установкой новых данных |
| **Слабые пароли** | PBKDF2-SHA256, 600 000 итераций, политика сложности |
| **Утечка информации** | Единое сообщение «Неверный логин или пароль» + фиктивная проверка хэша |
| **Clickjacking** | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| **MIME-sniffing** | `X-Content-Type-Options: nosniff` |
| **Mixed content** | HSTS при HTTPS |
| **Подмена IP** | `X-Forwarded-For` игнорируется, если `TRUSTED_PROXY_COUNT=0` |
| **Утечка стека** | Кастомные обработчики 400/403/404/405/413/429/500 |

### Важно перед продакшеном

- [ ] Установите `SESSION_COOKIE_SECURE=1` (работает только через HTTPS)
- [ ] Задайте `SECRET_KEY` из переменной окружения
- [ ] Уберите флаг `--demo` из инициализации
- [ ] Ограничьте права на файл `sport.db` (`chmod 600`)
- [ ] Запускайте за nginx/caddy и укажите `TRUSTED_PROXY_COUNT=1`
- [ ] Не публикуйте папки `instance/`, `backups/` в веб
- [ ] Отключите `FLASK_DEBUG`
- [ ] Настройте внешний бэкап (S3, rsync и т.п.)

---

## 💾 Резервное копирование

- Автоматически раз в час — фоновый поток в `backup.py`
- Консистентная копия через `sqlite3.Connection.backup()` (безопасно при работающей БД)
- Хранится последние **48 копий** (2 суток при часовом интервале)
- Формат имени: `sport_YYYYMMDD_HHMMSS.db`

Ручной бэкап:

```bash
python backup.py
```

---

## 🚢 Развёртывание

### Gunicorn (Linux/macOS)

```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

### Waitress (Windows)

```bash
pip install waitress
waitress-serve --listen=127.0.0.1:5000 app:app
```

### Пример systemd-юнита

```ini
[Unit]
Description=Sport Complex Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/sport-complex
Environment="SECRET_KEY=change-me"
Environment="SESSION_COOKIE_SECURE=1"
ExecStart=/opt/sport-complex/.venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Nginx reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name sport.example.com;

    ssl_certificate     /etc/letsencrypt/live/sport.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sport.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> При работе за одним nginx установите `TRUSTED_PROXY_COUNT=1`, чтобы `remote_addr` корректно вычислялся из `X-Forwarded-For`.

---

## ❓ FAQ

<details>
<summary><b>Услуги не появились на главной после <code>init_db.py</code></b></summary>

Проверь, что услуги действительно в базе:

```bash
python -c "import sqlite3; from config import Config; c=sqlite3.connect(Config.DATABASE); print(c.execute('SELECT id, title FROM services').fetchall())"
```

Если список пуст — убедись, что запускаешь **тот же** `init_db.py` и **ту же** базу (`Config.DATABASE`).
</details>

<details>
<summary><b>Как сбросить базу и начать заново</b></summary>

```bash
# Останови сервер, затем:
del sport.db          # Windows
rm sport.db           # Linux/macOS
rmdir /s /q backups   # Windows
rm -rf backups        # Linux/macOS
python init_db.py
```
</details>

<details>
<summary><b>Забыл пароль администратора</b></summary>

Сгенерируй нового администратора:

```bash
python -c "
import sqlite3, os
from config import Config
from security import hash_password
pwd = os.environ.get('ADMIN_PASSWORD') or 'ChangeMe123!'
c = sqlite3.connect(Config.DATABASE)
c.execute('DELETE FROM users WHERE username = ?', ('admin',))
c.execute('INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, \"admin\")',
          ('admin', hash_password(pwd), 'Администратор'))
c.commit()
print('Новый пароль:', pwd)
"
```
</details>

<details>
<summary><b>Ошибка <code>UNIQUE constraint failed: bookings...</code></b></summary>

В базе остался старый уникальный индекс. Примени миграцию:

```bash
python migrate.py
```
</details>

<details>
<summary><b>Как отключить автобэкапы</b></summary>

```bash
set BACKUP_ENABLED=0        # Windows
export BACKUP_ENABLED=0     # Linux/macOS
```
</details>

---

## 📝 Лицензия

MIT License. См. файл [LICENSE](LICENSE).

---

## 🤝 Вклад

Pull requests приветствуются. Для крупных изменений сначала откройте issue, чтобы обсудить, что вы хотите изменить.

1. Форкните репозиторий
2. Создайте ветку (`git checkout -b feature/amazing-feature`)
3. Закоммитьте (`git commit -m 'Add amazing feature'`)
4. Запушьте (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

---

<p align="center">
  Сделано с ❤️ для спортивных комплексов
</p>
