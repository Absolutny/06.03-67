import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def _load_secret_key() -> bytes | str:
    """
    Секретный ключ для подписи сессий.
    1) переменная окружения SECRET_KEY (приоритет, рекомендуется для боевого режима);
    2) иначе ключ один раз генерируется и сохраняется в instance/secret_key,
       чтобы сессии не «слетали» при каждом перезапуске и работали в нескольких процессах.
    """
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key

    key_path = os.path.join(INSTANCE_DIR, 'secret_key')
    try:
        with open(key_path, 'r', encoding='utf-8') as f:
            key = f.read().strip()
            if len(key) >= 32:
                return key
    except FileNotFoundError:
        pass

    os.makedirs(INSTANCE_DIR, exist_ok=True)
    key = secrets.token_hex(32)
    # Файл создаётся с правами 0600 (на Windows флаг игнорируется системой)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


class Config:
    SECRET_KEY = _load_secret_key()

    # Путь к базе данных SQLite (можно переопределить переменной SPORT_DB)
    DATABASE = os.environ.get('SPORT_DB') or os.path.join(BASE_DIR, 'sport.db')
    BACKUP_DIR = os.environ.get('SPORT_BACKUP_DIR') or os.path.join(BASE_DIR, 'backups')
    BACKUP_ENABLED = _env_bool('BACKUP_ENABLED', True)
    BACKUP_INTERVAL_SECONDS = 3600       # ежечасовое резервное копирование (см. ТЗ)
    BACKUP_KEEP = 48                     # хранить последние 48 копий

    # Отладка выключена по умолчанию: отладчик Werkzeug позволяет выполнять код на сервере.
    DEBUG = _env_bool('FLASK_DEBUG', False)

    # Сетевые параметры. По умолчанию доступ только с локального компьютера.
    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = int(os.environ.get('PORT', '5000'))

    # Количество доверенных обратных прокси (nginx и т.п.), которым можно верить в X-Forwarded-For.
    # 0 — заголовок игнорируется целиком (защита от подмены IP).
    TRUSTED_PROXY_COUNT = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))

    # Сессии и cookie
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # В боевом режиме за HTTPS: SESSION_COOKIE_SECURE=1
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)   # абсолютный срок жизни сессии
    SESSION_IDLE_TIMEOUT = 30 * 60                    # выход при бездействии 30 минут
    SESSION_REFRESH_EACH_REQUEST = False

    # Ограничение размера запроса (защита от DoS большими телами)
    MAX_CONTENT_LENGTH = 64 * 1024

    # Не показывать пользователю подробности ошибок
    PROPAGATE_EXCEPTIONS = False
    TEMPLATES_AUTO_RELOAD = False
    JSON_SORT_KEYS = False
