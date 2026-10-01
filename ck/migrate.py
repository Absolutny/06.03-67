"""
Миграции БД. Запускается автоматически из init_db.py.
Также можно вызвать вручную: python migrate.py
"""
import sqlite3
import sys
from config import Config


def _table_columns(cur, table: str) -> set[str]:
    return {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(cur, table: str, column: str, ddl: str):
    if column not in _table_columns(cur, table):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        print(f"[MIGRATE] {table}.{column} добавлена")


def _ensure_unique_index(cur):
    """Пересоздать ux_bookings_active с корректным условием (rejected + cancelled не активны)."""
    cur.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='ux_bookings_active'")
    row = cur.fetchone()
    if row and row[0] and "'cancelled'" in row[0]:
        return
    cur.execute("DROP INDEX IF EXISTS ux_bookings_active")
    cur.execute("""
        CREATE UNIQUE INDEX ux_bookings_active
            ON bookings(client_id, service_id, booking_date)
            WHERE status NOT IN ('rejected', 'cancelled')
    """)
    print("[MIGRATE] ux_bookings_active пересоздан")


def _ensure_updated_at(cur):
    for table in ('users', 'services', 'bookings'):
        _add_column_if_missing(cur, table, 'updated_at',
                               'DATETIME DEFAULT CURRENT_TIMESTAMP')


def _ensure_triggers(cur):
    cur.executescript('''
        CREATE TRIGGER IF NOT EXISTS users_set_updated_at
        AFTER UPDATE OF username, password_hash, full_name, role ON users
        FOR EACH ROW BEGIN
            UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;

        CREATE TRIGGER IF NOT EXISTS services_set_updated_at
        AFTER UPDATE OF title, description, price ON services
        FOR EACH ROW BEGIN
            UPDATE services SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;

        CREATE TRIGGER IF NOT EXISTS bookings_set_updated_at
        AFTER UPDATE OF status, booking_date, service_id ON bookings
        FOR EACH ROW BEGIN
            UPDATE bookings SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;
    ''')


def run_migrations():
    conn = sqlite3.connect(Config.DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    try:
        _ensure_unique_index(cur)
        _ensure_updated_at(cur)
        _ensure_triggers(cur)
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
        print("[MIGRATE] Миграции применены.")
    except Exception as e:
        conn.rollback()
        print(f"[MIGRATE ERROR] {e}")
        sys.exit(1)
    finally:
        conn.close()


if __name__ == '__main__':
    run_migrations()