import os
import sqlite3
import threading
import time
from datetime import datetime

from config import Config


def make_backup() -> str | None:
    """Консистентная копия БД средствами SQLite (безопасна при работающем приложении)."""
    try:
        os.makedirs(Config.BACKUP_DIR, exist_ok=True)
        name = datetime.now().strftime('sport_%Y%m%d_%H%M%S.db')
        path = os.path.join(Config.BACKUP_DIR, name)
        src = sqlite3.connect(Config.DATABASE)
        dst = sqlite3.connect(path)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()

        backups = sorted(f for f in os.listdir(Config.BACKUP_DIR) if f.startswith('sport_') and f.endswith('.db'))
        for old in backups[:-Config.BACKUP_KEEP]:
            os.remove(os.path.join(Config.BACKUP_DIR, old))
        return path
    except Exception as e:
        print(f"[BACKUP ERROR] {e}")
        return None


def start_backup_thread():
    """Фоновое ежечасовое резервное копирование (требование ТЗ)."""
    def loop():
        while True:
            make_backup()
            time.sleep(Config.BACKUP_INTERVAL_SECONDS)
    threading.Thread(target=loop, name='db-backup', daemon=True).start()


if __name__ == '__main__':
    print(make_backup() or 'Резервная копия не создана')
