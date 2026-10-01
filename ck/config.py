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


def _load_secret_key():
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

    os.makedirs(INSTANCE_DIR, mode=0o700, exist_ok=True)
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


class Config:
    SECRET_KEY = _load_secret_key()

    DATABASE = os.environ.get('SPORT_DB') or os.path.join(BASE_DIR, 'sport.db')
    BACKUP_DIR = os.environ.get('SPORT_BACKUP_DIR') or os.path.join(BASE_DIR, 'backups')
    BACKUP_ENABLED = _env_bool('BACKUP_ENABLED', True)
    BACKUP_INTERVAL_SECONDS = 3600
    BACKUP_KEEP = 48

    DEBUG = _env_bool('FLASK_DEBUG', False)

    HOST = os.environ.get('HOST', '127.0.0.1')
    PORT = int(os.environ.get('PORT', '5000'))

    TRUSTED_PROXY_COUNT = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_IDLE_TIMEOUT = 30 * 60
    SESSION_REFRESH_EACH_REQUEST = False

    MAX_CONTENT_LENGTH = 64 * 1024

    # Бизнес-ограничения
    MAX_BOOKING_DAYS_AHEAD = 365
    MAX_ACTIVE_BOOKINGS = 20
    MAX_SERVICE_PRICE = 1_000_000

    # Ротация журнала аудита
    AUDIT_RETENTION_DAYS = 365

    PROPAGATE_EXCEPTIONS = False
    TEMPLATES_AUTO_RELOAD = False