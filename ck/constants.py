"""Единый источник ролей и статусов. Убирает хардкод строк по проекту."""

# Роли
ROLE_ADMIN = 'admin'
ROLE_TRAINER = 'trainer'
ROLE_CLIENT = 'client'
ALL_ROLES = (ROLE_ADMIN, ROLE_TRAINER, ROLE_CLIENT)

# Статусы заявок
ST_PENDING = 'pending'
ST_ACCEPTED = 'accepted'
ST_REJECTED = 'rejected'
ST_CANCELLED = 'cancelled'
ALL_STATUSES = (ST_PENDING, ST_ACCEPTED, ST_REJECTED, ST_CANCELLED)
ACTIVE_STATUSES = (ST_PENDING, ST_ACCEPTED)
CLOSED_STATUSES = (ST_REJECTED, ST_CANCELLED)