import os
import sqlite3
import threading
import time
from datetime import datetime

from config import Config


def make_backup() -> str | None:
    try:
        os.makedirs(Config.BACKUP_DIR, mode=0o700, exist_ok=True)
        name = datetime.now().strftime('sport_%Y%m%d_%H%M%S.db')
        path = os.path.join(Config.BACKUP_DIR, name)
        src = sqlite3.connect(Config.DATABASE)
        dst = sqlite3.connect(path)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()

        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

        backups = sorted(f for f in os.listdir(Config.BACKUP_DIR)
                         if f.startswith('sport_') and f.endswith('.db'))
        for old in backups[:-Config.BACKUP_KEEP]:
            os.remove(os.path.join(Config.BACKUP_DIR, old))
        return path
    except Exception as e:
        print(f"[BACKUP ERROR] {e}")
        return None


def start_backup_thread():
    def loop():
        # Первая ротация — сразу при старте, чтобы не ждать час
        try:
            from audit import rotate_audit_logs
            rotate_audit_logs()
        except Exception as e:
            print(f"[AUDIT ROTATE ERROR] {e}")

        while True:
            make_backup()
            # Раз в час — бэкап; раз в сутки — ещё и ротация аудита
            try:
                from audit import rotate_audit_logs
                rotate_audit_logs()
            except Exception:
                pass
            time.sleep(Config.BACKUP_INTERVAL_SECONDS)

    threading.Thread(target=loop, name='db-backup', daemon=True).start()


if __name__ == '__main__':
    print(make_backup() or 'Резервная копия не создана')