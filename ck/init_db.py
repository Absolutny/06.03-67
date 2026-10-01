"""
Инициализация БД.

  python init_db.py                 — создать таблицы, услуги и администратора
                                      (пароль из ADMIN_PASSWORD или случайный, печатается один раз)
  python init_db.py --demo          — плюс 5 тестовых учёток (trainer1/2, client1/2/3)
                                      ТОЛЬКО ДЛЯ РАЗРАБОТКИ
  python init_db.py --services-only — только создать/обновить каталог услуг
"""
import argparse
import os
import secrets
import sqlite3
import sys

from config import Config, BASE_DIR
from security import hash_password, validate_password_policy
from constants import ROLE_ADMIN, ROLE_TRAINER, ROLE_CLIENT
from migrate import run_migrations

DEMO_USERS = [
    ('admin',    'Admin123!',   'Администратор Комплекса', ROLE_ADMIN),
    ('trainer1', 'Trainer123!', 'Смирнов Алексей',         ROLE_TRAINER),
    ('trainer2', 'Trainer123!', 'Кузнецова Мария',         ROLE_TRAINER),
    ('client1',  'Client123!',  'Иванов Иван',             ROLE_CLIENT),
    ('client2',  'Client123!',  'Петрова Анна',            ROLE_CLIENT),
    ('client3',  'Client123!',  'Сидоров Пётр',            ROLE_CLIENT),
]

SERVICES = [
    ('Бассейн', 'Посещение плавательного бассейна 50 м. Дорожки 1–6, свободное плавание.', 500.0),
    ('Тренажёрный зал', 'Разовое посещение зала: кардио, свободные веса, базовые тренажёры.', 400.0),
    ('Групповое занятие: Йога', 'Занятие по хатха-йоге в группе до 15 человек с сертифицированным инструктором.', 600.0),
    ('Персональная тренировка', 'Индивидуальное занятие с тренером 60 минут. Программа под ваши цели.', 1500.0),
    ('Сауна и хаммам', 'Посещение финской сауны и турецкого хаммама, 2 часа, с полотенцами.', 700.0),
    ('Скалодром', 'Разовое посещение скалодрома, трассы 4a–7b. Прокат страховки включён.', 900.0),
]


def _generate_password() -> str:
    return 'Aa1!' + secrets.token_urlsafe(12)


def _create_tables(cur):
    with open(os.path.join(BASE_DIR, 'schema.sql'), encoding='utf-8') as f:
        try:
            cur.executescript(f.read())
        except sqlite3.IntegrityError as e:
            print(f"[WARN] Создание индекса: {e}")


def _migrate_roles(cur):
    cur.execute(f"UPDATE users SET role = '{ROLE_TRAINER}' WHERE role = 'staff'")
    cur.execute(f"UPDATE users SET role = '{ROLE_CLIENT}' WHERE role NOT IN "
                f"('{ROLE_ADMIN}', '{ROLE_TRAINER}', '{ROLE_CLIENT}')")


def _ensure_services(cur) -> int:
    added = 0
    for title, desc, price in SERVICES:
        cur.execute("SELECT id FROM services WHERE title = ?", (title,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO services (title, description, price) VALUES (?, ?, ?)",
                (title, desc, price))
            added += 1
    return added


def _ensure_demo_users(cur) -> int:
    added = 0
    for username, password, full_name, role in DEMO_USERS:
        cur.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,))
        if cur.fetchone():
            continue
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), full_name, role))
        added += 1
    return added


def _ensure_admin(cur) -> None:
    cur.execute(f"SELECT COUNT(*) FROM users WHERE role = '{ROLE_ADMIN}'")
    if cur.fetchone()[0] > 0:
        print("[OK] Администратор уже существует — новый не создаём.")
        return

    password = os.environ.get('ADMIN_PASSWORD') or _generate_password()
    ok, msg = validate_password_policy(password, 'admin')
    if not ok:
        sys.exit(f"[ERROR] ADMIN_PASSWORD не соответствует политике: {msg}")

    cur.execute(
        "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
        ('admin', hash_password(password), 'Администратор Комплекса', ROLE_ADMIN))
    print("=" * 60)
    print(" Создан администратор.  Логин: admin")
    if not os.environ.get('ADMIN_PASSWORD'):
        print(f" Пароль: {password}")
        print(" Сохраните его сейчас — повторно он показан не будет.")
    print("=" * 60)


def init_db(demo: bool = False, services_only: bool = False):
    conn = sqlite3.connect(Config.DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    _create_tables(cur)
    _migrate_roles(cur)

    added = _ensure_services(cur)
    print(f"[OK] Услуги: +{added} (всего {len(SERVICES)} в каталоге).")

    if services_only:
        conn.commit()
        conn.close()
        run_migrations()
        print("[OK] Каталог услуг обновлён.")
        return

    if demo:
        print("[!] Режим --demo: тестовые учётки с публичными паролями. Только для разработки.")
        added = _ensure_demo_users(cur)
        if added:
            print(f"[OK] Добавлено пользователей: {added}.")
            for u, p, _, r in DEMO_USERS:
                print(f"       {u:10s} / {p:12s}  ({r})")
        else:
            print("[OK] Тестовые пользователи уже созданы.")
    else:
        _ensure_admin(cur)

    conn.commit()
    conn.close()

    run_migrations()
    print("[OK] База данных успешно инициализирована.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Инициализация БД СпортКомплекс')
    parser.add_argument('--demo', action='store_true',
                        help='Создать тестовые учётки (trainer1/2, client1/2/3). Только для разработки.')
    parser.add_argument('--services-only', action='store_true',
                        help='Только создать/обновить каталог услуг.')
    args = parser.parse_args()
    init_db(demo=args.demo, services_only=args.services_only)