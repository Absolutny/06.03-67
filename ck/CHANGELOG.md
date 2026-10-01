# Changelog

## [Unreleased]
### Added
- Финансовый отчёт `/admin/reports` (выручка и востребованность услуг)
- Health-check `/healthz`
- Ротация журнала аудита (`AUDIT_RETENTION_DAYS`)
- Модуль `constants.py` — единый источник ролей и статусов
- Модуль `helpers.py` — общая валидация услуг и создания пользователей
- Модуль `reports.py` — агрегация финансовых данных
- Миграции с `PRAGMA user_version`
- Поля `updated_at` и триггеры для `users`, `services`, `bookings`
- `COLLATE NOCASE` для `users.username` на уровне схемы
- `--demo` флаг в `init_db.py`

### Fixed
- Stored XSS через `service.title` в inline `onsubmit`
- Неатомарное удаление аккаунта в `profile_delete`
- Необработанный `IntegrityError` при удалении услуги с историей заявок
- Race condition в проверке `MAX_ACTIVE_BOOKINGS` (теперь `BEGIN IMMEDIATE`)
- `my_bookings` доступна только клиентам (`@client_required`)
- Права `0o700`/`0o600` для папки бэкапов и файлов
- Убран `__import__('os')` в `app.py`
- Убран мёртвый `Config.JSON_SORT_KEYS`

### Security
- Запрет символов `' " < >` в названии услуги
- Централизованный confirm через `data-confirm` (совместимо со строгим CSP)
- Логирование отклонённых дублей в `audit_logs`