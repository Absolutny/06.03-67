import re
from flask import request, session, has_request_context
from db import connect
from rate_limit import get_remote_address
from config import Config

_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')


def _clean(value, limit: int):
    if value is None:
        return None
    return _CONTROL.sub(' ', str(value))[:limit]


def log_event(event_type: str, description: str, user_id: int = None, username: str = None):
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
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Не удалось записать событие: {e}")


def rotate_audit_logs(keep_days: int = None) -> int:
    """
    Удалить записи аудита старше keep_days.
    Возвращает число удалённых строк. Безопасно вызывать при работающем приложении.
    """
    if keep_days is None:
        keep_days = Config.AUDIT_RETENTION_DAYS
    try:
        conn = connect(timeout=5)
        try:
            cur = conn.execute(
                "DELETE FROM audit_logs WHERE timestamp < datetime('now', ?)",
                (f'-{keep_days} days',),
            )
            conn.commit()
            deleted = cur.rowcount
        finally:
            conn.close()
        if deleted:
            print(f"[AUDIT ROTATE] Удалено записей: {deleted} (старше {keep_days} дней)")
        return deleted
    except Exception as e:
        print(f"[AUDIT ROTATE ERROR] {e}")
        return 0