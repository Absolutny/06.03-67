-- ============================================================
--  Спортивный Комплекс — схема базы данных SQLite
-- ============================================================

-- ------------------------------------------------------------
--  Пользователи
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'client',  -- 'admin' | 'trainer' | 'client'
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
--  Услуги
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
--  Заявки (записи) клиентов
--  Статусы:
--    pending   — на рассмотрении тренером
--    accepted  — подтверждена тренером
--    rejected  — отклонена тренером
--    cancelled — отменена клиентом
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bookings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    INTEGER NOT NULL,
    service_id   INTEGER NOT NULL,
    booking_date TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id)  REFERENCES users(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

-- ------------------------------------------------------------
--  Журнал аудита безопасности
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    TEXT,
    event_type  TEXT NOT NULL,
    description TEXT,
    ip_address  TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  Индексы
-- ============================================================

-- Ускорение выборок по заявкам
CREATE INDEX IF NOT EXISTS idx_bookings_client ON bookings(client_id);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(status);

-- Ускорение сортировки журнала аудита
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

-- ------------------------------------------------------------
--  Защита от дублей:
--  один клиент не может дважды записаться на одну услугу
--  на одну и ту же дату, ПОКА запись активна.
--  Отклонённые (rejected) и отменённые (cancelled) заявки
--  НЕ считаются активными и слот не занимают.
-- ------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS ux_bookings_active
    ON bookings(client_id, service_id, booking_date)
    WHERE status NOT IN ('rejected', 'cancelled');