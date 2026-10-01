"""Общая бизнес-логика: валидация услуг, создание пользователей, парсинг цен."""
import math
import re
import sqlite3

from db import execute_query, execute_commit
from security import (
    hash_password, validate_username, validate_full_name, validate_password_policy,
)
from constants import ALL_ROLES

MAX_SERVICE_PRICE = 1_000_000

# Запрещённые символы в названии услуги: защита от stored XSS в JS-контексте
_FORBIDDEN_TITLE = re.compile(r"['\"<>]")


# ---------- Услуги ----------

def parse_price(value, max_price: float = MAX_SERVICE_PRICE):
    """Вернуть (price, None) либо (None, error_msg)."""
    if value is None:
        return None, "Цена не указана."
    try:
        price = float(str(value).replace(',', '.'))
    except (ValueError, TypeError):
        return None, "Некорректная цена."
    if not math.isfinite(price) or price <= 0 or price > max_price:
        return None, f"Цена должна быть больше 0 и не превышать {max_price:,.0f}."
    return round(price, 2), None


def validate_service_title(title: str):
    if not isinstance(title, str) or not (2 <= len(title) <= 100):
        return False, "Название услуги: от 2 до 100 символов."
    if _FORBIDDEN_TITLE.search(title):
        return False, "Название не должно содержать символы ' \" < >."
    return True, ""


def upsert_service(service_id, title, description, price_raw):
    """
    Создать (service_id=None) или обновить услугу.
    Возвращает (ok, error_msg).
    """
    ok, msg = validate_service_title(title)
    if not ok:
        return False, msg
    price, err = parse_price(price_raw)
    if err:
        return False, err

    if service_id is None:
        execute_commit(
            "INSERT INTO services (title, description, price) VALUES (?, ?, ?)",
            (title, description, price),
        )
    else:
        execute_commit(
            "UPDATE services SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, price, service_id),
        )
    return True, ""


# ---------- Пользователи ----------

def create_user(username: str, password: str, full_name: str, role: str):
    """
    Создать пользователя.
    Возвращает (user_id, error_msg). Ошибка — не исключение, а строка для flash.
    """
    if role not in ALL_ROLES:
        return None, "Недопустимая роль."

    for ok, msg in (validate_username(username),
                    validate_full_name(full_name),
                    validate_password_policy(password, username)):
        if not ok:
            return None, msg

    existing = execute_query(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,), one=True)
    if existing:
        return None, "Пользователь с таким логином уже существует."

    try:
        uid = execute_commit(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), full_name, role),
        )
    except sqlite3.IntegrityError:
        return None, "Пользователь с таким логином уже существует."
    return uid, None