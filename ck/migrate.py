"""Одноразовая миграция: пересоздание уникального индекса заявок."""
import sqlite3
from config import Config

conn = sqlite3.connect(Config.DATABASE)
conn.execute("DROP INDEX IF EXISTS ux_bookings_active")
conn.execute("""
    CREATE UNIQUE INDEX ux_bookings_active
        ON bookings(client_id, service_id, booking_date)
        WHERE status NOT IN ('rejected', 'cancelled')
""")
conn.commit()

# Проверка
row = conn.execute(
    "SELECT sql FROM sqlite_master WHERE name = 'ux_bookings_active'"
).fetchone()
print("Новый индекс:")
print(row[0] if row else "— не создан —")

conn.close()
print("[OK] Миграция завершена.")