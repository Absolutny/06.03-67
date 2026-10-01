import threading
import time
from collections import defaultdict, deque
from functools import wraps
from flask import request, render_template, flash, make_response

_lock = threading.Lock()

# Окна для входа
LOGIN_IP_MAX = 5            # неудачных попыток с одного IP
LOGIN_IP_WINDOW = 300       # за 5 минут
LOGIN_USER_MAX = 10         # неудачных попыток на один логин (с любых IP — защита от распределённого подбора)
LOGIN_USER_WINDOW = 900     # за 15 минут


def get_remote_address() -> str:
    """
    IP клиента. Заголовку X-Forwarded-For НЕ доверяем: его может подставить кто угодно
    и обойти лимиты. Если приложение стоит за прокси, включите TRUSTED_PROXY_COUNT —
    тогда ProxyFix в app.py корректно выставит remote_addr.
    """
    return request.remote_addr or '0.0.0.0'


class SlidingWindowLimiter:
    """Потокобезопасный лимитер событий по скользящему окну."""

    def __init__(self):
        self._events = defaultdict(deque)

    def _prune(self, key, window, now):
        q = self._events[key]
        while q and now - q[0] >= window:
            q.popleft()
        if not q:
            self._events.pop(key, None)
            return None
        return q

    def count(self, key, window) -> int:
        now = time.time()
        with _lock:
            q = self._prune(key, window, now)
            return len(q) if q else 0

    def hit(self, key, window):
        now = time.time()
        with _lock:
            self._prune(key, window, now)
            self._events[key].append(now)
            # Защита от неограниченного роста памяти
            if len(self._events) > 50000:
                for k in list(self._events)[:10000]:
                    self._events.pop(k, None)

    def retry_after(self, key, window) -> int:
        now = time.time()
        with _lock:
            q = self._prune(key, window, now)
            if not q:
                return 0
            return max(1, int(window - (now - q[0])))

    def clear(self, key):
        with _lock:
            self._events.pop(key, None)

    def reset(self):
        with _lock:
            self._events.clear()


_login_limiter = SlidingWindowLimiter()
_generic_limiter = SlidingWindowLimiter()


def _norm_user(username: str) -> str:
    return (username or '').strip().lower()[:64]


# --- Ограничение попыток входа ---

def is_rate_limited(ip: str, username: str = '') -> bool:
    if _login_limiter.count(('ip', ip), LOGIN_IP_WINDOW) >= LOGIN_IP_MAX:
        return True
    if username and _login_limiter.count(('user', _norm_user(username)), LOGIN_USER_WINDOW) >= LOGIN_USER_MAX:
        return True
    return False


def record_failed_attempt(ip: str, username: str = ''):
    _login_limiter.hit(('ip', ip), LOGIN_IP_WINDOW)
    if username:
        _login_limiter.hit(('user', _norm_user(username)), LOGIN_USER_WINDOW)


def clear_failed_attempts(ip: str, username: str = ''):
    _login_limiter.clear(('ip', ip))
    if username:
        _login_limiter.clear(('user', _norm_user(username)))


def limit_login_attempts(f):
    """Декоратор ограничения попыток авторизации (считаются только POST-запросы)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            ip = get_remote_address()
            username = request.form.get('username', '')
            if is_rate_limited(ip, username):
                from audit import log_event
                wait = max(
                    _login_limiter.retry_after(('ip', ip), LOGIN_IP_WINDOW),
                    _login_limiter.retry_after(('user', _norm_user(username)), LOGIN_USER_WINDOW),
                    1,
                )
                log_event("RATE_LIMITED", f"Блокировка попыток входа (логин: {username[:64]})")
                flash("Слишком много неудачных попыток входа. Попробуйте позже.", "danger")
                resp = make_response(render_template('login.html'), 429)
                resp.headers['Retry-After'] = str(wait)
                return resp
        return f(*args, **kwargs)
    return decorated_function


# --- Общий лимитер для остальных действий (регистрация, запись и т.д.) ---

def rate_limit(name: str, max_calls: int, window: int, per_user: bool = False):
    """
    Декоратор: не более max_calls POST-запросов за window секунд
    (по IP или по пользователю, если per_user=True и он вошёл).
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method == 'POST':
                from flask import session
                ident = session.get('user_id') if per_user and 'user_id' in session else get_remote_address()
                key = (name, ident)
                if _generic_limiter.count(key, window) >= max_calls:
                    from audit import log_event
                    log_event("RATE_LIMITED", f"Превышен лимит запросов: {name}")
                    resp = make_response(render_template(
                        'error.html', code=429,
                        title="Слишком много запросов",
                        message="Вы отправляете запросы слишком часто. Повторите попытку позже."), 429)
                    resp.headers['Retry-After'] = str(_generic_limiter.retry_after(key, window))
                    return resp
                _generic_limiter.hit(key, window)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def reset_all():
    """Сброс всех счётчиков (используется в тестах)."""
    _login_limiter.reset()
    _generic_limiter.reset()
