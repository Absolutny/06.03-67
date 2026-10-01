import math
import sqlite3
from datetime import date, timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from db import close_db, execute_query, execute_commit, execute_write
from security import (
    hash_password, verify_password, verify_dummy, validate_password_policy,
    sanitize_input, validate_username, validate_full_name,
    login_required, admin_required, trainer_required, client_required,
    set_security_headers, csrf_protect, generate_csrf_token, load_current_user, start_session,
)
from rate_limit import (
    limit_login_attempts, record_failed_attempt, clear_failed_attempts,
    get_remote_address, rate_limit,
)
from audit import log_event

app = Flask(__name__)
app.config.from_object(Config)

# Доверяем X-Forwarded-* только если явно указано число прокси перед приложением
if Config.TRUSTED_PROXY_COUNT > 0:
    n = Config.TRUSTED_PROXY_COUNT
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

app.teardown_appcontext(close_db)
app.before_request(load_current_user)
app.before_request(csrf_protect)
app.after_request(set_security_headers)
app.jinja_env.globals['csrf_token'] = generate_csrf_token

MAX_BOOKING_DAYS_AHEAD = 365
MAX_ACTIVE_BOOKINGS = 20


# ============================================================
#  ОБЩИЕ СТРАНИЦЫ
# ============================================================

@app.route('/')
def index():
    services = execute_query("SELECT * FROM services ORDER BY id DESC")
    return render_template('dashboard.html', services=services)


@app.route('/register', methods=['GET', 'POST'])
@rate_limit('register', max_calls=10, window=3600)
def register():
    """Самостоятельная регистрация клиентов."""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''), 32)
        password = request.form.get('password', '')
        full_name = sanitize_input(request.form.get('full_name', ''), 100)

        for ok, msg in (validate_username(username), validate_full_name(full_name),
                        validate_password_policy(password, username)):
            if not ok:
                flash(msg, "danger")
                return render_template('register.html')

        existing = execute_query("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,), one=True)
        if existing:
            flash("Пользователь с таким логином уже существует.", "danger")
            return render_template('register.html')

        try:
            execute_commit(
                "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, 'client')",
                (username, hash_password(password), full_name)
            )
        except sqlite3.IntegrityError:
            flash("Пользователь с таким логином уже существует.", "danger")
            return render_template('register.html')

        log_event("REGISTER", f"Зарегистрирован новый клиент: {username}", username=username)
        flash("Регистрация успешна! Теперь вы можете войти.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# ============================================================
#  АВТОРИЗАЦИЯ / ВЫХОД
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
@limit_login_attempts
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''), 64)
        password = request.form.get('password', '')
        ip = get_remote_address()

        user = execute_query("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,), one=True)

        if user and verify_password(user['password_hash'], password):
            clear_failed_attempts(ip, username)
            start_session(user)

            log_event("LOGIN_SUCCESS", f"Вход пользователя {user['username']} ({user['role']})",
                      user_id=user['id'], username=user['username'])
            flash("Вы успешно вошли в систему.", "success")
            return redirect(url_for('index'))

        if not user:
            verify_dummy(password)   # одинаковое время ответа для существующих и несуществующих логинов
        record_failed_attempt(ip, username)
        log_event("LOGIN_FAILED", f"Неудачный вход: {username}", username=username[:64] or 'anonymous')
        flash("Неверный логин или пароль.", "danger")

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    log_event("LOGOUT", "Пользователь вышел из системы")
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for('login'))


# ============================================================
#  ПРОФИЛЬ И ПАРОЛЬ
# ============================================================

@app.route('/profile')
@login_required
def profile():
    """Страница профиля: данные пользователя и статистика."""
    user = execute_query(
        "SELECT id, username, full_name, role, created_at FROM users WHERE id = ?",
        (session['user_id'],), one=True)

    stats = {}
    if session.get('role') == 'client':
        row = execute_query('''
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'pending'  THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
            FROM bookings WHERE client_id = ?
        ''', (session['user_id'],), one=True)
        stats = dict(row) if row else {}
    elif session.get('role') in ('trainer', 'admin'):
        row = execute_query('''
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'pending'  THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected
            FROM bookings
        ''', one=True)
        stats = dict(row) if row else {}

    return render_template('profile.html', user=user, stats=stats)


@app.route('/profile/edit', methods=['POST'])
@login_required
@rate_limit('profile_edit', max_calls=20, window=900, per_user=True)
def profile_edit():
    """Редактирование ФИО в профиле."""
    full_name = sanitize_input(request.form.get('full_name', ''), 100)
    ok, msg = validate_full_name(full_name)
    if not ok:
        flash(msg, "danger")
        return redirect(url_for('profile'))

    execute_commit("UPDATE users SET full_name = ? WHERE id = ?", (full_name, session['user_id']))
    log_event("PROFILE_UPDATED", f"Пользователь изменил ФИО на '{full_name}'")
    flash("Профиль обновлён.", "success")
    return redirect(url_for('profile'))


@app.route('/profile/delete', methods=['POST'])
@login_required
@rate_limit('profile_delete', max_calls=5, window=3600, per_user=True)
def profile_delete():
    """Удаление собственного аккаунта (только для клиентов)."""
    if session.get('role') != 'client':
        flash("Удаление аккаунта доступно только клиентам.", "warning")
        return redirect(url_for('profile'))

    password = request.form.get('password', '')
    user = execute_query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    if not user or not verify_password(user['password_hash'], password):
        log_event("ACCOUNT_DELETE_FAILED", "Неверный пароль при удалении аккаунта")
        flash("Неверный пароль. Удаление отменено.", "danger")
        return redirect(url_for('profile'))

    # Удаляем заявки и аккаунт (foreign_keys ON)
    execute_commit("DELETE FROM bookings WHERE client_id = ?", (user['id'],))
    execute_commit("DELETE FROM users WHERE id = ?", (user['id'],))
    log_event("ACCOUNT_DELETED", f"Клиент {user['username']} удалил свой аккаунт",
              username=user['username'])
    session.clear()
    flash("Аккаунт удалён. Спасибо, что были с нами.", "info")
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@rate_limit('change_password', max_calls=10, window=900, per_user=True)
def change_password():
    """Смена собственного пароля. После смены остальные сессии пользователя становятся недействительными."""
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        user = execute_query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
        if not verify_password(user['password_hash'], current):
            log_event("PASSWORD_CHANGE_FAILED", "Неверный текущий пароль при смене пароля")
            flash("Текущий пароль указан неверно.", "danger")
            return render_template('change_password.html')
        if new != confirm:
            flash("Новый пароль и подтверждение не совпадают.", "danger")
            return render_template('change_password.html')
        if verify_password(user['password_hash'], new):
            flash("Новый пароль должен отличаться от текущего.", "danger")
            return render_template('change_password.html')
        ok, msg = validate_password_policy(new, user['username'])
        if not ok:
            flash(msg, "danger")
            return render_template('change_password.html')

        execute_commit("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user['id']))
        log_event("PASSWORD_CHANGED", "Пользователь изменил пароль")
        fresh = execute_query("SELECT * FROM users WHERE id = ?", (user['id'],), one=True)
        start_session(fresh)   # текущая сессия продолжает работать, остальные — нет
        flash("Пароль успешно изменён.", "success")
        return redirect(url_for('index'))

    return render_template('change_password.html')


# ============================================================
#  ФУНКЦИОНАЛ АДМИНИСТРАТОРА
# ============================================================

@app.route('/admin/add_service', methods=['GET', 'POST'])
@admin_required
def add_service():
    """Создание новой услуги (Админ)."""
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 500)

        if not (2 <= len(title) <= 100):
            flash("Название услуги: от 2 до 100 символов.", "danger")
            return render_template('add_service.html')
        try:
            price = float(request.form.get('price', '').replace(',', '.'))
        except ValueError:
            flash("Некорректная цена.", "danger")
            return render_template('add_service.html')
        if not math.isfinite(price) or price <= 0 or price > 1_000_000:
            flash("Цена должна быть больше 0 и не превышать 1 000 000.", "danger")
            return render_template('add_service.html')
        price = round(price, 2)

        execute_commit(
            "INSERT INTO services (title, description, price) VALUES (?, ?, ?)",
            (title, description, price)
        )
        log_event("SERVICE_CREATED", f"Администратор создал услугу '{title}' ({price} руб.)")
        flash(f"Услуга '{title}' успешно добавлена!", "success")
        return redirect(url_for('index'))

    return render_template('add_service.html')


@app.route('/admin/hire_trainer', methods=['GET', 'POST'])
@admin_required
def hire_trainer():
    """Найм нового тренера (Админ)."""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''), 32)
        password = request.form.get('password', '')
        full_name = sanitize_input(request.form.get('full_name', ''), 100)

        for ok, msg in (validate_username(username), validate_full_name(full_name),
                        validate_password_policy(password, username)):
            if not ok:
                flash(msg, "danger")
                return render_template('hire_trainer.html')

        existing = execute_query("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,), one=True)
        if existing:
            flash("Пользователь с таким логином уже зарегистрирован.", "danger")
            return render_template('hire_trainer.html')

        try:
            execute_commit(
                "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, 'trainer')",
                (username, hash_password(password), full_name)
            )
        except sqlite3.IntegrityError:
            flash("Пользователь с таким логином уже зарегистрирован.", "danger")
            return render_template('hire_trainer.html')

        log_event("TRAINER_HIRED", f"Администратор зарегистрировал тренера {full_name} ({username})")
        flash(f"Тренер '{full_name}' успешно нанят!", "success")
        return redirect(url_for('index'))

    return render_template('hire_trainer.html')


@app.route('/admin/service/<int:service_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_service(service_id):
    """Редактирование услуги (Админ)."""
    service = execute_query("SELECT * FROM services WHERE id = ?", (service_id,), one=True)
    if not service:
        flash("Услуга не найдена.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 500)
        if not (2 <= len(title) <= 100):
            flash("Название услуги: от 2 до 100 символов.", "danger")
            return render_template('edit_service.html', service=service)
        try:
            price = float(request.form.get('price', '').replace(',', '.'))
        except ValueError:
            flash("Некорректная цена.", "danger")
            return render_template('edit_service.html', service=service)
        if not math.isfinite(price) or price <= 0 or price > 1_000_000:
            flash("Цена должна быть больше 0 и не превышать 1 000 000.", "danger")
            return render_template('edit_service.html', service=service)

        execute_commit(
            "UPDATE services SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, round(price, 2), service_id))
        log_event("SERVICE_UPDATED", f"Администратор изменил услугу #{service_id} ('{title}')")
        flash("Услуга обновлена.", "success")
        return redirect(url_for('index'))

    return render_template('edit_service.html', service=service)


@app.route('/admin/service/<int:service_id>/delete', methods=['POST'])
@admin_required
def delete_service(service_id):
    """Удаление услуги. Запрещаем, если есть активные (pending/accepted) заявки."""
    active = execute_query(
        "SELECT COUNT(*) AS c FROM bookings WHERE service_id = ? AND status IN ('pending','accepted')",
        (service_id,), one=True)['c']
    if active:
        flash(f"Нельзя удалить услугу: есть {active} активных заявок.", "warning")
        return redirect(url_for('index'))

    changed = execute_write("DELETE FROM services WHERE id = ?", (service_id,))
    if not changed:
        flash("Услуга не найдена.", "warning")
        return redirect(url_for('index'))

    log_event("SERVICE_DELETED", f"Администратор удалил услугу #{service_id}")
    flash("Услуга удалена.", "success")
    return redirect(url_for('index'))


@app.route('/audit_log')
@admin_required
def audit_log():
    per_page = 50
    page = request.args.get('page', 1, type=int) or 1
    page = max(1, min(page, 10_000))
    total = execute_query("SELECT COUNT(*) AS c FROM audit_logs", one=True)['c']
    logs = execute_query(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, (page - 1) * per_page))
    pages = max(1, (total + per_page - 1) // per_page)
    return render_template('audit_log.html', logs=logs, page=page, pages=pages, total=total)


# ============================================================
#  ФУНКЦИОНАЛ ТРЕНЕРА
# ============================================================

@app.route('/trainer/bookings')
@trainer_required
def trainer_bookings():
    """Просмотр заявок тренером."""
    bookings = execute_query('''
        SELECT b.id, u.full_name as client_name, s.title as service_title,
               b.booking_date, b.status, b.created_at
        FROM bookings b
        JOIN users u ON b.client_id = u.id
        JOIN services s ON b.service_id = s.id
        ORDER BY CASE WHEN b.status = 'pending' THEN 0 ELSE 1 END, b.created_at DESC
    ''')
    return render_template('trainer_bookings.html', bookings=bookings)


@app.route('/trainer/booking/<int:booking_id>/<action>', methods=['POST'])
@trainer_required
def process_booking(booking_id, action):
    """Принятие или отклонение заявки тренером (только для заявок «на рассмотрении»)."""
    if action not in ('accept', 'reject'):
        flash("Недопустимое действие.", "danger")
        return redirect(url_for('trainer_bookings'))

    new_status = 'accepted' if action == 'accept' else 'rejected'
    # Атомарная смена статуса: обработать можно только заявку в статусе pending
    changed = execute_write(
        "UPDATE bookings SET status = ? WHERE id = ? AND status = 'pending'", (new_status, booking_id))
    if not changed:
        flash("Заявка не найдена или уже обработана.", "warning")
        return redirect(url_for('trainer_bookings'))

    status_text = "принята" if action == 'accept' else "отклонена"
    log_event("BOOKING_PROCESSED", f"Тренер {session['username']} изменил статус заявки #{booking_id} на {new_status}")
    flash(f"Заявка #{booking_id} {status_text}.", "info")
    return redirect(url_for('trainer_bookings'))


# ============================================================
#  ФУНКЦИОНАЛ КЛИЕНТА
# ============================================================

@app.route('/book_service/<int:service_id>', methods=['POST'])
@client_required
@rate_limit('book', max_calls=30, window=3600, per_user=True)
def book_service(service_id):
    """Отправка заявки на запись клиентом."""
    service = execute_query("SELECT id FROM services WHERE id = ?", (service_id,), one=True)
    if not service:
        flash("Выбранная услуга не найдена.", "danger")
        return redirect(url_for('index'))

    raw_date = sanitize_input(request.form.get('booking_date', ''), 10)
    try:
        booking_date = date.fromisoformat(raw_date)
    except ValueError:
        flash("Укажите корректную дату записи.", "warning")
        return redirect(url_for('index'))

    today = date.today()
    if booking_date < today:
        flash("Нельзя записаться на прошедшую дату.", "warning")
        return redirect(url_for('index'))
    if booking_date > today + timedelta(days=MAX_BOOKING_DAYS_AHEAD):
        flash("Запись возможна не более чем на год вперёд.", "warning")
        return redirect(url_for('index'))

    active = execute_query(
        "SELECT COUNT(*) AS c FROM bookings WHERE client_id = ? AND status = 'pending'",
        (session['user_id'],), one=True)['c']
    if active >= MAX_ACTIVE_BOOKINGS:
        flash("Слишком много заявок на рассмотрении. Дождитесь ответа тренера.", "warning")
        return redirect(url_for('my_bookings'))

    try:
        execute_commit(
            "INSERT INTO bookings (client_id, service_id, booking_date, status) VALUES (?, ?, ?, 'pending')",
            (session['user_id'], service_id, booking_date.isoformat())
        )
    except sqlite3.IntegrityError:
        flash("У вас уже есть активная заявка на эту услугу на выбранную дату.", "warning")
        return redirect(url_for('my_bookings'))

    log_event("BOOKING_SUBMITTED", f"Клиент {session['username']} создал заявку на услугу #{service_id}")
    flash("Заявка успешно отправлена! Ожидайте подтверждения тренера.", "success")
    return redirect(url_for('my_bookings'))


@app.route('/my_bookings')
@login_required
def my_bookings():
    """Просмотр клиентом своих заявок с фильтром по статусу."""
    status_filter = request.args.get('status', 'all')
    allowed = {'all', 'pending', 'accepted', 'rejected', 'cancelled'}
    if status_filter not in allowed:
        status_filter = 'all'

    sql = '''
        SELECT b.id, s.title, s.price, b.booking_date, b.status, b.created_at
        FROM bookings b
        JOIN services s ON b.service_id = s.id
        WHERE b.client_id = ?
    '''
    args = [session['user_id']]
    if status_filter != 'all':
        sql += " AND b.status = ?"
        args.append(status_filter)
    sql += " ORDER BY b.created_at DESC"

    bookings = execute_query(sql, tuple(args))

    # Сводка по статусам для бейджей фильтра
    counts = execute_query('''
        SELECT status, COUNT(*) AS c FROM bookings WHERE client_id = ? GROUP BY status
    ''', (session['user_id'],))
    counts_map = {row['status']: row['c'] for row in counts}

    return render_template('my_bookings.html',
                           bookings=bookings,
                           status_filter=status_filter,
                           counts=counts_map)


@app.route('/booking/<int:booking_id>/cancel', methods=['POST'])
@client_required
@rate_limit('cancel_booking', max_calls=60, window=3600, per_user=True)
def cancel_booking(booking_id):
    """
    Отмена собственной записи клиентом.
    Доступна в статусах pending и accepted, в любой момент времени.
    """
    booking = execute_query(
        "SELECT id, status, booking_date FROM bookings WHERE id = ? AND client_id = ?",
        (booking_id, session['user_id']), one=True)

    if not booking:
        # Не раскрываем, существует ли запись у другого клиента
        flash("Запись не найдена.", "warning")
        return redirect(url_for('my_bookings'))

    if booking['status'] == 'cancelled':
        flash("Эта запись уже отменена.", "info")
        return redirect(url_for('my_bookings'))
    if booking['status'] == 'rejected':
        flash("Отклонённые заявки нельзя отменить.", "info")
        return redirect(url_for('my_bookings'))

    # Атомарная смена статуса: обрабатываем только заявки в разрешённых статусах
    changed = execute_write(
        "UPDATE bookings SET status = 'cancelled' WHERE id = ? AND client_id = ? AND status IN ('pending', 'accepted')",
        (booking_id, session['user_id']))

    if not changed:
        flash("Не удалось отменить запись. Возможно, её статус уже изменился.", "warning")
        return redirect(url_for('my_bookings'))

    log_event("BOOKING_CANCELLED",
              f"Клиент {session['username']} отменил заявку #{booking_id} (дата: {booking['booking_date']})")
    flash(f"Запись на {booking['booking_date']} отменена.", "success")
    return redirect(url_for('my_bookings'))


# ============================================================
#  ОБРАБОТКА ОШИБОК (без утечки технических подробностей)
# ============================================================

def _error(code, title, message):
    return render_template('error.html', code=code, title=title, message=message), code


@app.errorhandler(400)
def bad_request(e):
    if getattr(e, 'description', '') == 'csrf':
        return _error(400, "Запрос отклонён",
                      "Форма устарела или не прошла проверку безопасности. Обновите страницу и повторите действие.")
    return _error(400, "Некорректный запрос", "Сервер не смог обработать запрос.")


@app.errorhandler(403)
def forbidden(e):
    return _error(403, "Доступ запрещён", "У вас недостаточно прав для просмотра этой страницы.")


@app.errorhandler(404)
def not_found(e):
    return _error(404, "Страница не найдена", "Запрашиваемая страница не найдена.")


@app.errorhandler(405)
def method_not_allowed(e):
    return _error(405, "Метод не поддерживается", "Для этого адреса данный тип запроса недопустим.")


@app.errorhandler(413)
def too_large(e):
    return _error(413, "Слишком большой запрос", "Размер отправленных данных превышает допустимый.")


@app.errorhandler(429)
def too_many(e):
    return _error(429, "Слишком много запросов", "Повторите попытку позже.")


@app.errorhandler(500)
def internal_error(e):
    return _error(500, "Внутренняя ошибка сервера", "Произошла внутренняя ошибка. Обратитесь к администратору.")


# ============================================================
#  ТОЧКА ВХОДА
# ============================================================

if __name__ == '__main__':
    host, debug = Config.HOST, Config.DEBUG
    # Отладчик Werkzeug = удалённое выполнение кода. В сеть он не выставляется никогда.
    if debug and host not in ('127.0.0.1', 'localhost', '::1'):
        print("[SECURITY] Режим отладки отключён: он недопустим при доступе из сети.")
        debug = False

    if Config.BACKUP_ENABLED and (not debug or __import__('os').environ.get('WERKZEUG_RUN_MAIN') == 'true'):
        from backup import start_backup_thread
        start_backup_thread()

    app.run(host=host, port=Config.PORT, debug=debug)