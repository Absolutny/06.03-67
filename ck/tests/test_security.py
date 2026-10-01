"""
Автотесты защитных механизмов.   Запуск:  python -m unittest discover -s tests -v
Тесты работают на временной БД и не затрагивают sport.db.
"""
import os
import re
import sys
import tempfile
import unittest
from datetime import date, timedelta

_tmp = tempfile.mkdtemp()
os.environ['SPORT_DB'] = os.path.join(_tmp, 'test.db')
os.environ['SPORT_BACKUP_DIR'] = os.path.join(_tmp, 'bk')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import init_db      # noqa: E402
import rate_limit   # noqa: E402
from app import app  # noqa: E402

init_db.init_db(demo=True)
app.config['TESTING'] = False   # обработчики ошибок должны работать как в бою


def token(client, url='/login'):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, user, pwd, **kw):
    return client.post('/login', data={'username': user, 'password': pwd,
                                       'csrf_token': token(client)}, **kw)


def post(client, url, data=None, page='/'):
    d = dict(data or {})
    d['csrf_token'] = token(client, page)
    return client.post(url, data=d)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        rate_limit.reset_all()
        self.c = app.test_client()

    # --- CSRF ---
    def test_post_without_csrf_rejected(self):
        self.assertEqual(self.c.post('/login', data={'username': 'admin', 'password': 'Admin123!'}).status_code, 400)

    def test_post_with_foreign_origin_rejected(self):
        t = token(self.c)
        r = self.c.post('/login', data={'username': 'admin', 'password': 'Admin123!', 'csrf_token': t},
                        headers={'Origin': 'http://evil.example'})
        self.assertEqual(r.status_code, 400)

    def test_logout_requires_post(self):
        login(self.c, 'client', 'Client123!')
        self.assertEqual(self.c.get('/logout').status_code, 405)

    # --- Заголовки ---
    def test_security_headers(self):
        h = self.c.get('/').headers
        self.assertIn("script-src 'self'", h['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline', h['Content-Security-Policy'])
        self.assertEqual(h['X-Frame-Options'], 'DENY')
        self.assertEqual(h['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(h['Cache-Control'], 'no-store')

    def test_no_external_resources(self):
        html = self.c.get('/').get_data(as_text=True)
        self.assertNotIn('cdn.jsdelivr.net', html)
        self.assertNotIn('googleapis', html)

    # --- RBAC ---
    def test_role_access(self):
        self.assertEqual(self.c.get('/audit_log').status_code, 302)       # аноним -> на вход
        login(self.c, 'client', 'Client123!')
        for url in ('/audit_log', '/admin/add_service', '/admin/hire_trainer', '/trainer/bookings'):
            self.assertEqual(self.c.get(url).status_code, 403, url)
        c2 = app.test_client()
        login(c2, 'trainer', 'Trainer123!')
        self.assertEqual(c2.get('/trainer/bookings').status_code, 200)
        self.assertEqual(c2.get('/audit_log').status_code, 403)

    def test_admin_cannot_book_only_clients(self):
        login(self.c, 'admin', 'Admin123!')
        r = post(self.c, '/book_service/1', {'booking_date': (date.today() + timedelta(days=2)).isoformat()})
        self.assertEqual(r.status_code, 403)

    def test_forged_role_cookie_not_trusted(self):
        login(self.c, 'client', 'Client123!')
        with self.c.session_transaction() as s:
            s['role'] = 'admin'          # подмена роли внутри сессии
        self.assertEqual(self.c.get('/audit_log').status_code, 403)   # роль берётся из БД

    # --- Перебор паролей ---
    def test_bruteforce_lockout_and_xff_spoof(self):
        for i in range(5):
            # смена X-Forwarded-For не должна сбрасывать счётчик
            r = self.c.post('/login', data={'username': 'admin', 'password': 'wrong%d' % i,
                                            'csrf_token': token(self.c)},
                            headers={'X-Forwarded-For': '10.0.0.%d' % i})
            self.assertEqual(r.status_code, 200)
        r = login(self.c, 'admin', 'Admin123!')       # верный пароль, но уже блокировка
        self.assertEqual(r.status_code, 429)
        self.assertIn('Retry-After', r.headers)

    def test_login_message_is_generic(self):
        a = login(self.c, 'admin', 'nope').get_data(as_text=True)
        b = login(self.c, 'no_such_user', 'nope').get_data(as_text=True)
        self.assertIn('Неверный логин или пароль', a)
        self.assertIn('Неверный логин или пароль', b)

    # --- Пароли / регистрация ---
    def test_register_validation(self):
        bad = [('ab', 'Ivan Ivanov', 'Str0ng!Pass'),
               ('user<script>', 'Ivan Ivanov', 'Str0ng!Pass'),
               ('newuser1', 'Ivan Ivanov', 'weak'),
               ('newuser1', 'Ivan Ivanov', 'Admin123!'),
               ('newuser1', 'Ivan Ivanov', 'x' * 200 + 'A1!'),
               ('newuser1', 'Ivan Ivanov', 'Newuser1!x')]       # содержит логин
        for u, n, p in bad:
            r = post(self.c, '/register', {'username': u, 'full_name': n, 'password': p}, '/register')
            self.assertEqual(r.status_code, 200, (u, p[:10]))
        r = post(self.c, '/register', {'username': 'goodUser', 'full_name': 'Ivan Ivanov', 'password': 'Str0ng!Pass'}, '/register')
        self.assertEqual(r.status_code, 302)
        r = post(self.c, '/register', {'username': 'GOODUSER', 'full_name': 'Dup', 'password': 'Str0ng!Pass'}, '/register')
        self.assertEqual(r.status_code, 200)    # логин без учёта регистра уникален

    # --- XSS ---
    def test_xss_escaped_once(self):
        login(self.c, 'admin', 'Admin123!')
        post(self.c, '/admin/add_service', {'title': 'Yoga <b>& "co"', 'description': '<script>alert(1)</script>',
                                            'price': '100'}, '/admin/add_service')
        html = self.c.get('/').get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertNotIn('&amp;amp;', html)       # нет двойного экранирования

    # --- Валидация услуг и записей ---
    def test_service_price_validation(self):
        login(self.c, 'admin', 'Admin123!')
        for price in ('nan', 'inf', '-5', '0', '1e12', 'abc', ''):
            r = post(self.c, '/admin/add_service', {'title': 'Test', 'description': '', 'price': price}, '/admin/add_service')
            self.assertEqual(r.status_code, 200, price)

    def test_booking_rules_and_idor(self):
        login(self.c, 'client', 'Client123!')
        d = lambda n: (date.today() + timedelta(days=n)).isoformat()
        self.assertEqual(post(self.c, '/book_service/1', {'booking_date': d(-1)}).status_code, 302)
        self.assertEqual(post(self.c, '/book_service/1', {'booking_date': 'garbage'}).status_code, 302)
        self.assertEqual(post(self.c, '/book_service/9999', {'booking_date': d(3)}).status_code, 302)
        count = lambda: self.c.get('/my_bookings').get_data(as_text=True).count('<tr>') - 1
        before = count()                                   # заявки с некорректными данными не создались
        self.assertEqual(post(self.c, '/book_service/1', {'booking_date': d(3)}).status_code, 302)
        post(self.c, '/book_service/1', {'booking_date': d(3)})        # дубль
        self.assertEqual(count(), before + 1)

    def test_booking_processed_once(self):
        login(self.c, 'client', 'Client123!')
        post(self.c, '/book_service/2', {'booking_date': (date.today() + timedelta(days=5)).isoformat()})
        t = app.test_client()
        login(t, 'trainer', 'Trainer123!')
        from db import connect
        bid = connect().execute("SELECT id FROM bookings WHERE status='pending' ORDER BY id DESC").fetchone()['id']
        post(t, f'/trainer/booking/{bid}/accept', page='/trainer/bookings')
        r = post(t, f'/trainer/booking/{bid}/reject', page='/trainer/bookings')   # повторная обработка
        self.assertEqual(r.status_code, 302)
        self.assertEqual(connect().execute("SELECT status FROM bookings WHERE id=?", (bid,)).fetchone()['status'], 'accepted')
        self.assertEqual(post(t, f'/trainer/booking/99999/accept', page='/trainer/bookings').status_code, 302)
        self.assertEqual(post(t, f'/trainer/booking/{bid}/delete', page='/trainer/bookings').status_code, 302)

    # --- Сессии ---
    def test_password_change_invalidates_other_sessions(self):
        other = app.test_client()
        login(other, 'client', 'Client123!')
        login(self.c, 'client', 'Client123!')
        r = post(self.c, '/change_password', {'current_password': 'Client123!', 'new_password': 'N3w!Secret#1',
                                              'confirm_password': 'N3w!Secret#1'}, '/change_password')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get('/my_bookings').status_code, 200)      # текущая сессия жива
        self.assertEqual(other.get('/my_bookings').status_code, 302)       # остальные — нет
        # вернуть исходный пароль напрямую в БД (Client123! теперь в списке запрещённых для выбора)
        from db import connect
        from security import hash_password
        conn = connect()
        conn.execute("UPDATE users SET password_hash=? WHERE username='client'", (hash_password('Client123!'),))
        conn.commit()
        conn.close()

    def test_idle_timeout(self):
        login(self.c, 'client', 'Client123!')
        with self.c.session_transaction() as s:
            s['last_seen'] = 0
        self.assertEqual(self.c.get('/my_bookings').status_code, 302)

    def test_cookie_flags(self):
        r = self.c.get('/login')
        cookie = r.headers.get('Set-Cookie', '')
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Lax', cookie)

    # --- Прочее ---
    def test_error_pages_do_not_leak(self):
        r = self.c.get('/no/such/page')
        self.assertEqual(r.status_code, 404)
        self.assertNotIn('Traceback', r.get_data(as_text=True))

    def test_oversized_body_rejected(self):
        r = self.c.post('/login', data={'username': 'a' * 200000, 'password': 'x', 'csrf_token': 'x'})
        self.assertEqual(r.status_code, 413)

    def test_audit_log_forging_prevented(self):
        login(self.c, 'admin\nFAKE_EVENT', 'x')
        from db import connect
        rows = connect().execute("SELECT description FROM audit_logs WHERE event_type='LOGIN_FAILED'").fetchall()
        self.assertTrue(all('\n' not in r['description'] for r in rows))


if __name__ == '__main__':
    unittest.main(verbosity=2)
