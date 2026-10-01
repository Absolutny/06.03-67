"""Аналитика выручки и востребованности услуг."""
from db import execute_query
from constants import ST_ACCEPTED


def financial_report(date_from: str, date_to: str, service_id: int | None = None):
    """
    Агрегация по услугам за период [date_from, date_to].
    Возвращает список словарей: service_id, title, total, accepted, revenue.
    """
    sql = '''
        SELECT s.id                                AS service_id,
               s.title                             AS title,
               s.price                             AS price,
               COUNT(b.id)                         AS total,
               SUM(CASE WHEN b.status = ? THEN 1 ELSE 0 END) AS accepted,
               SUM(CASE WHEN b.status = ? THEN s.price ELSE 0 END) AS revenue
        FROM services s
        LEFT JOIN bookings b
               ON b.service_id = s.id
              AND b.booking_date BETWEEN ? AND ?
    '''
    args = [ST_ACCEPTED, ST_ACCEPTED, date_from, date_to]
    if service_id:
        sql += " WHERE s.id = ?"
        args.append(service_id)
    sql += " GROUP BY s.id, s.title, s.price ORDER BY revenue DESC, s.title ASC"
    return execute_query(sql, tuple(args))


def report_summary(rows):
    total = sum(r['total'] for r in rows)
    accepted = sum(r['accepted'] for r in rows)
    revenue = sum((r['revenue'] or 0) for r in rows)
    return {'total': total, 'accepted': accepted, 'revenue': round(revenue, 2)}