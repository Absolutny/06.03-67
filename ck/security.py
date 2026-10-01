import hashlib
import hmac
import re
import secrets
import time
import unicodedata
from functools import wraps
from urllib.parse import urlparse

from flask import session, redirect, url_for, flash, request, abort, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. Криптография и пароли ---

PBKDF2_METHOD = 'pbkdf2:sha256:600000'   # PBKDF2-HMAC-SHA256, 600 000 итераций (рекомендация OWASP)

# Хэш-«пустышка»: проверяется, когда логин не найден, чтобы время ответа не выдавало существование аккаунта
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method=PBKDF2_METHOD, salt_length=16)

COMMON_PASSWORDS = {
    'password1!', 'password123!', 'qwerty123!', 'qwerty123', 'admin123!', 'admin123',
    'welcome1!', 'passw0rd!', 'p@ssw0rd', 'p@ssword1', 'letmein123!', '12345678a!',
    'trainer123!', 'client123!', 'iloveyou1!', 'qwertyuiop1!', 'zaq12wsx!', '1q2w3e4r!',
}


def hash_password(password: str) -> str:
    """Безопасное хэширование пароля с использованием pbkdf2:sha256 и случайной соли."""
    return generate_password_hash(password, method=PBKDF2_METHOD, salt_length=16)


def verify_password(password_hash: str, password: str) -> bool:
    """Проверка совпадения открытого пароля с хэшем."""
    if not password_hash or not password or len(password) > 128:
        return False
    try:
        return check_password_hash(password_hash, password)
    except ValueError:
        return False


def verify_dummy(password: str) -> None:
    """Выравнивание времени ответа, если пользователя не существует."""
    if password and len(password) <= 128:
        check_password_hash(_DUMMY_HASH, password)


def validate_password_policy(password: str, username: str = '') -> tuple[bool, str]:
    """
    Политика паролей:
    - длина 8–128 символов;
    - заглавная и строчная буквы, цифра, специальный символ;
    - пароль не должен содержать логин и не должен быть в списке распространённых.
    """
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов."
    if len(password) > 128:
        return False, "Пароль не должен быть длиннее 128 символов."
    if not re.search(r"[A-ZА-ЯЁ]", password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву."
    if not re.search(r"[a-zа-яё]", password):
        return False, "Пароль должен содержать хотя бы одну строчную букву."
    if not re.search(r"\d", password):
        return False, "Пароль должен содержать хотя бы одну цифру."
    if not re.search(r"[^\w\s]|_", password):
        return False, "Пароль должен содержать хотя бы один спецсимвол (!@#$%^&*)."
    if password.lower() in COMMON_PASSWORDS:
        return False, "Этот пароль слишком распространён. Придумайте другой."
    if username and len(username) >= 3 and username.lower() in password.lower():
        return False, "Пароль не должен содержать логин."
    return True, ""


# --- 2. Проверка и очистка ввода ---

_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')


def sanitize_input(text: str, max_len: int = 500) -> str:
    """
    Нормализация строки: Unicode NFKC, удаление управляющих символов, обрезка пробелов и длины.
    HTML здесь намеренно НЕ экранируется: экранирование выполняет Jinja2 при выводе
    (иначе данные портятся двойным экранированием, например «&amp;amp;»).
    """
    if not isinstance(text, str):
        return ''
    text = unicodedata.normalize('NFKC', text)
    text = _CONTROL_CHARS.sub('', text).strip()
    return text[:max_len]


def validate_username(username: str) -> tuple[bool, str]:
    if not USERNAME_RE.match(username):
        return False, "Логин: 3–32 символа, только латинские буквы, цифры и знаки _ . -"
    return True, ""


def validate_full_name(full_name: str) -> tuple[bool, str]:
    if not (2 <= len(full_name) <= 100):
        return False, "ФИО должно содержать от 2 до 100 символов."
    if re.search(r'[<>]', full_name):
        return False, "ФИО содержит недопустимые символы."
    return True, ""


# --- 3. CSRF-защита ---

def generate_csrf_token() -> str:
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


def _same_origin(url: str) -> bool:
    try:
        return urlparse(url).netloc == request.host
    except ValueError:
        return False


def csrf_protect():
    """
    before_request: все изменяющие запросы должны содержать верный CSRF-токен.
    Дополнительно проверяется заголовок Origin/Referer.
    """
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    if request.endpoint == 'static':
        return None

    expected = session.get('_csrf')
    sent = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
    if not expected or not sent or not hmac.compare_digest(expected, sent):
        from audit import log_event
        log_event("CSRF_BLOCKED", f"Отклонён запрос без валидного CSRF-токена: {request.method} {request.path}")
        abort(400, description="csrf")

    origin = request.headers.get('Origin') or request.headers.get('Referer')
    if origin and not _same_origin(origin):
        from audit import log_event
        log_event("CSRF_BLOCKED", f"Отклонён запрос с чужим Origin: {request.path}")
        abort(400, description="csrf")
    return None


# --- 4. Сессии: актуализация пользователя, тайм-аут бездействия ---

def password_fingerprint(password_hash: str) -> str:
    """Отпечаток хэша пароля: при смене пароля все прежние сессии становятся недействительными."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:20]


def start_session(user) -> None:
    """Создание новой сессии после успешного входа (защита от фиксации сессии)."""
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['pv'] = password_fingerprint(user['password_hash'])
    session['last_seen'] = int(time.time())
    generate_csrf_token()


def load_current_user():
    """
    before_request: роль и существование пользователя проверяются по БД при каждом запросе
    (а не берутся из cookie на веру), плюс тайм-аут бездействия.
    """
    if request.endpoint == 'static' or 'user_id' not in session:
        return None

    from db import execute_query
    now = int(time.time())
    idle = current_app.config['SESSION_IDLE_TIMEOUT']

    if now - session.get('last_seen', 0) > idle:
        session.clear()
        flash("Сессия завершена из-за бездействия. Войдите снова.", "warning")
        return None

    user = execute_query("SELECT id, username, role, password_hash FROM users WHERE id = ?",
                         (session['user_id'],), one=True)
    if (user is None
            or session.get('pv') != password_fingerprint(user['password_hash'])):
        session.clear()
        flash("Сессия недействительна. Войдите снова.", "warning")
        return None

    session['username'] = user['username']
    session['role'] = user['role']
    session['last_seen'] = now
    g.user = user
    return None


# --- 5. Разграничение прав и авторизация (RBAC) ---

def _deny(message: str):
    from audit import log_event
    log_event("ACCESS_DENIED", f"{request.method} {request.path}: недостаточно прав")
    return abort(403)


def login_required(f):
    """Декоратор: доступ разрешен только вошедшим пользователям."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Для доступа к этой странице необходимо авторизоваться.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    """Декоратор: доступ только для перечисленных ролей."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Требуется авторизация.", "warning")
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                return _deny("У вас недостаточно прав для выполнения этой операции.")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


admin_required = role_required('admin')
trainer_required = role_required('trainer', 'admin')
client_required = role_required('client')


# --- 6. Защитные HTTP-заголовки ---

CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'"
)


def set_security_headers(response):
    """Добавление заголовков безопасности в HTTP-ответ."""
    h = response.headers
    h['X-Content-Type-Options'] = 'nosniff'
    h['X-Frame-Options'] = 'DENY'
    h['X-XSS-Protection'] = '0'   # устаревший фильтр отключается намеренно, защиту даёт CSP
    h['Content-Security-Policy'] = CSP
    h['Referrer-Policy'] = 'same-origin'
    h['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    h['Cross-Origin-Opener-Policy'] = 'same-origin'
    h['Cross-Origin-Resource-Policy'] = 'same-origin'
    if request.is_secure or current_app.config.get('SESSION_COOKIE_SECURE'):
        h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Страницы с персональными данными не должны оседать в кэше браузера/прокси
    if request.endpoint != 'static':
        h['Cache-Control'] = 'no-store'
        h['Pragma'] = 'no-cache'
    return response
