import sqlite3
from flask import g
from config import Config


def connect(timeout: float = 10.0) -> sqlite3.Connection:
    """Создание подключения с безопасными настройками SQLite."""
    conn = sqlite3.connect(Config.DATABASE, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")      # контроль внешних ключей
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def get_db():
    """Получение подключения к базе данных SQLite (одно на запрос)."""
    if 'db' not in g:
        g.db = connect()
    return g.db


def close_db(e=None):
    """Закрытие подключения к базе данных по завершении запроса."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def execute_query(query, args=(), one=False):
    """
    Безопасный параметризованный SQL-запрос для исключения SQL-инъекций.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_commit(query, args=()):
    """Выполнение операции запись/изменение с commit. Возвращает id вставленной строки."""
    db = get_db()
    try:
        cur = db.execute(query, args)
        db.commit()
    except Exception:
        db.rollback()
        raise
    last_id = cur.lastrowid
    cur.close()
    return last_id


def execute_write(query, args=()):
    """Запись с commit. Возвращает число затронутых строк (для атомарных проверок)."""
    db = get_db()
    try:
        cur = db.execute(query, args)
        db.commit()
    except Exception:
        db.rollback()
        raise
    count = cur.rowcount
    cur.close()
    return count
