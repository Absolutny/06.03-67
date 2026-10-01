"""
Инициализация и миграция базы данных.

  python init_db.py          — создать таблицы, услуги и администратора
                               (пароль из ADMIN_PASSWORD или случайный, выводится ОДИН раз)
  python init_db.py --demo   — дополнительно создать тестовых пользователей с известными
                               паролями (ТОЛЬКО для разработки!)
"""
import os
import secrets
import sqlite3
import sys

from config import Config, BASE_DIR
from security import hash_password, validate_password_policy

# Демо-пользователи (только при --demo)
DEMO_USERS = [
    ('admin',   'Admin123!',   'Администратор Комплекса', 'admin'),
    ('trainer', 'Trainer123!', 'Тренер Тренеров',         'trainer'),
    ('client',  'Client123!',  'Иванов Иван',             'client'),
]

# Услуги — обычные данные приложения, создаются ВСЕГДА
SERVICES = [
    ('Бассейн',
     'Посещение плавательного бассейна 50 м. Дорожки 1–6, свободное плавание.',
     500.0),
    ('Тренажёрный зал',
     'Разовое посещение зала: кардио, свободные веса, базовые тренажёры.',
     400.0),
    ('Групповое занятие: Йога',
     'Занятие по хатха-йоге в группе до 15 человек с сертифицированным инструктором.',
     600.0),
    ('Персональная тренировка',
     'Индивидуальное занятие с тренером 60 минут. Программа под ваши цели.',
     1500.0),
    ('Сауна и хаммам',
     'Посещение финской сауны и турецкого хаммама, 2 часа, с полотенцами.',
     700.0),
    ('Скалодром',
     'Разовое посещение скалодрома, трассы 4a–7b. Прокат страховки включён.',
     900.0),
]


def _generate_password() -> str:
    # Гарантированно соответствует политике паролей
    return 'Aa1!' + secrets.token_urlsafe(12)


def ensure_services(cursor):
    """Создать отсутствующие услуги. Существующие (по title) не трогает."""
    added = 0
    for title, desc, price in SERVICES:
        cursor.execute("SELECT id FROM services WHERE title = ?", (title,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO services (title, description, price) VALUES (?, ?, ?)",
                (title, desc, price))
            added += 1
    return added


def init_db(demo: bool = False):
    conn = sqlite3.connect(Config.DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    with open(os.path.join(BASE_DIR, 'schema.sql'), encoding='utf-8') as f:
        try:
            cursor.executescript(f.read())
        except sqlite3.IntegrityError as e:
            print(f"[WARN] Не удалось создать уникальный индекс записей: {e}")

    # Миграция ролей
    cursor.execute("UPDATE users SET role = 'trainer' WHERE role = 'staff'")
    cursor.execute("UPDATE users SET role = 'client' WHERE role NOT IN ('admin', 'trainer', 'client')")

    # 1. Услуги — создаются ВСЕГДА
    added = ensure_services(cursor)
    if added:
        print(f"[OK] Добавлено услуг: {added} (всего {len(SERVICES)} в каталоге).")
    else:
        print(f"[OK] Все {len(SERVICES)} услуг уже есть в базе.")

    # 2. Администратор — если пользователей вообще нет
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0 and not demo:
        password = os.environ.get('ADMIN_PASSWORD') or _generate_password()
        ok, msg = validate_password_policy(password, 'admin')
        if not ok:
            conn.close()
            sys.exit(f"[ERROR] ADMIN_PASSWORD не соответствует политике паролей: {msg}")
        cursor.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, 'admin')",
            ('admin', hash_password(password), 'Администратор Комплекса'))
        print("=" * 60)
        print(" Создан администратор.  Логин: admin")
        if not os.environ.get('ADMIN_PASSWORD'):
            print(f" Пароль: {password}")
            print(" Сохраните его сейчас — повторно он показан не будет.")
        print("=" * 60)

    # 3. Демо-пользователи — только по флагу
    if demo:
        print("[!] Режим --demo: тестовые аккаунты с известными паролями. Не используйте в боевом режиме.")
        for username, password, full_name, role in DEMO_USERS:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                    (username, hash_password(password), full_name, role))

    conn.commit()
    conn.close()
    print("[OK] База данных успешно инициализирована.")


if __name__ == '__main__':
    init_db(demo='--demo' in sys.argv)