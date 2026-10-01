import re
from flask import request, session, has_request_context
from db import connect
from rate_limit import get_remote_address

_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')


def _clean(value, limit: int):
    """Убираем переводы строк/управляющие символы (защита от подделки записей журнала) и режем длину."""
    if value is None:
        return None
    return _CONTROL.sub(' ', str(value))[:limit]


def log_event(event_type: str, description: str, user_id: int = None, username: str = None):
    """Запись события безопасности в журнал аудита (отдельное соединение, чтобы запись не терялась при откате запроса)."""
    try:
        if has_request_context():
            ip = get_remote_address()
            uid = user_id or session.get('user_id')
            uname = username or session.get('username', 'anonymous')
        else:
            ip, uid, uname = '127.0.0.1', user_id, username or 'system'

        conn = connect(timeout=5)
        try:
            conn.execute(
                '''INSERT INTO audit_logs (user_id, username, event_type, description, ip_address)
                   VALUES (?, ?, ?, ?, ?)''',
                (uid, _clean(uname, 64), _clean(event_type, 32), _clean(description, 500), _clean(ip, 45)),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:  # журнал не должен ронять приложение
        print(f"[AUDIT LOG ERROR] Не удалось записать событие: {e}")
