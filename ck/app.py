import os
import sqlite3
from datetime import date, timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from db import get_db, close_db, execute_query, execute_commit, execute_write
from security import (
    hash_password, verify_password, verify_dummy, validate_password_policy,
    sanitize_input, validate_full_name,
    login_required, admin_required, trainer_required, client_required,
    set_security_headers, csrf_protect, generate_csrf_token, load_current_user, start_session,
)
from rate_limit import (
    limit_login_attempts, record_failed_attempt, clear_failed_attempts,
    get_remote_address, rate_limit,
)
from audit import log_event
from helpers import create_user, upsert_service, parse_price
from reports import financial_report, report_summary
from constants import (
    ROLE_ADMIN, ROLE_TRAINER, ROLE_CLIENT,
    ST_PENDING, ST_ACCEPTED, ST_REJECTED, ST_CANCELLED,
    ACTIVE_STATUSES,
)

app = Flask(__name__)
app.config.from_object(Config)

if Config.TRUSTED_PROXY_COUNT > 0:
    n = Config.TRUSTED_PROXY_COUNT
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

app.teardown_appcontext(close_db)
app.before_request(load_current_user)
app.before_request(csrf_protect)
app.after_request(set_security_headers)
app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ============================================================
#  HEALTH
# ============================================================

@app.route('/healthz')
def healthz():
    """Liveness-проба. Без БД — чтобы не падать при её недоступности."""
    return 'ok', 200, {'Content-Type': 'text/plain; charset=utf-8'}


# ============================================================
#  ОБЩИЕ СТРАНИЦЫ
# ============================================================

@app.route('/')
def index():
    services = execute_query("SELECT * FROM services ORDER BY id ASC")
    return render_template('dashboard.html', services=services)


@app.route('/register', methods=['GET', 'POST'])
@rate_limit('register', max_calls=10, window=3600)
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''), 32)
        password = request.form.get('password', '')
        full_name = sanitize_input(request.form.get('full_name', ''), 100)

        uid, err = create_user(username, password, full_name, ROLE_CLIENT)
        if err:
            log_event("REGISTER_FAILED", f"Отклонена регистрация '{username}': {err}",
                      username=username or 'anonymous')
            flash(err, "danger")
            return render_template('register.html')

        log_event("REGISTER", f"Зарегистрирован новый клиент: {username}", username=username)
        flash("Регистрация успешна! Теперь вы можете войти.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# ============================================================
#  АВТОРИЗАЦИЯ
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
            verify_dummy(password)
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
#  ПРОФИЛЬ
# ============================================================

@app.route('/profile')
@login_required
def profile():
    user = execute_query(
        "SELECT id, username, full_name, role, created_at FROM users WHERE id = ?",
        (session['user_id'],), one=True)

    stats = {}
    if session.get('role') == ROLE_CLIENT:
        row = execute_query('''
            SELECT COUNT(*) AS total,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS accepted,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS cancelled
            FROM bookings WHERE client_id = ?
        ''', (ST_PENDING, ST_ACCEPTED, ST_REJECTED, ST_CANCELLED, session['user_id']), one=True)
        stats = dict(row) if row else {}
    elif session.get('role') in (ROLE_TRAINER, ROLE_ADMIN):
        row = execute_query('''
            SELECT COUNT(*) AS total,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS accepted,
                SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS rejected
            FROM bookings
        ''', (ST_PENDING, ST_ACCEPTED, ST_REJECTED), one=True)
        stats = dict(row) if row else {}

    return render_template('profile.html', user=user, stats=stats)


@app.route('/profile/edit', methods=['POST'])
@login_required
@rate_limit('profile_edit', max_calls=20, window=900, per_user=True)
def profile_edit():
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
    if session.get('role') != ROLE_CLIENT:
        flash("Удаление аккаунта доступно только клиентам.", "warning")
        return redirect(url_for('profile'))

    password = request.form.get('password', '')
    user = execute_query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    if not user or not verify_password(user['password_hash'], password):
        log_event("ACCOUNT_DELETE_FAILED", "Неверный пароль при удалении аккаунта")
        flash("Неверный пароль. Удаление отменено.", "danger")
        return redirect(url_for('profile'))

    # Одна транзакция: либо удалится всё, либо ничего
    db = get_db()
    try:
        db.execute("DELETE FROM bookings WHERE client_id = ?", (user['id'],))
        db.execute("DELETE FROM users WHERE id = ?", (user['id'],))
        db.commit()
    except Exception:
        db.rollback()
        log_event("ACCOUNT_DELETE_FAILED", "Ошибка при удалении аккаунта")
        flash("Не удалось удалить аккаунт. Попробуйте позже.", "danger")
        return redirect(url_for('profile'))

    log_event("ACCOUNT_DELETED", f"Клиент {user['username']} удалил свой аккаунт",
              username=user['username'])
    session.clear()
    flash("Аккаунт удалён. Спасибо, что были с нами.", "info")
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@rate_limit('change_password', max_calls=10, window=900, per_user=True)
def change_password():
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
        start_session(fresh)
        flash("Пароль успешно изменён.", "success")
        return redirect(url_for('index'))

    return render_template('change_password.html')


# ============================================================
#  АДМИНИСТРАТОР
# ============================================================

@app.route('/admin/add_service', methods=['GET', 'POST'])
@admin_required
def add_service():
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 500)
        ok, err = upsert_service(None, title, description, request.form.get('price', ''))
        if not ok:
            flash(err, "danger")
            return render_template('add_service.html')
        log_event("SERVICE_CREATED", f"Администратор создал услугу '{title}'")
        flash(f"Услуга '{title}' успешно добавлена!", "success")
        return redirect(url_for('index'))
    return render_template('add_service.html')


@app.route('/admin/service/<int:service_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_service(service_id):
    service = execute_query("SELECT * FROM services WHERE id = ?", (service_id,), one=True)
    if not service:
        flash("Услуга не найдена.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 500)
        ok, err = upsert_service(service_id, title, description, request.form.get('price', ''))
        if not ok:
            flash(err, "danger")
            return render_template('edit_service.html', service=service)
        log_event("SERVICE_UPDATED", f"Администратор изменил услугу #{service_id} ('{title}')")
        flash("Услуга обновлена.", "success")
        return redirect(url_for('index'))

    return render_template('edit_service.html', service=service)


@app.route('/admin/service/<int:service_id>/delete', methods=['POST'])
@admin_required
def delete_service(service_id):
    active = execute_query(
        "SELECT COUNT(*) AS c FROM bookings WHERE service_id = ? AND status IN (?, ?)",
        (service_id, ST_PENDING, ST_ACCEPTED), one=True)['c']
    if active:
        flash(f"Нельзя удалить услугу: есть {active} активных заявок.", "warning")
        return redirect(url_for('index'))

    try:
        changed = execute_write("DELETE FROM services WHERE id = ?", (service_id,))
    except sqlite3.IntegrityError:
        log_event("SERVICE_DELETE_FAILED",
                  f"Услуга #{service_id} имеет связанные заявки в истории")
        flash("Услугу нельзя удалить: остались заявки в истории (отклонённые или отменённые).", "warning")
        return redirect(url_for('index'))

    if not changed:
        flash("Услуга не найдена.", "warning")
        return redirect(url_for('index'))

    log_event("SERVICE_DELETED", f"Администратор удалил услугу #{service_id}")
    flash("Услуга удалена.", "success")
    return redirect(url_for('index'))


@app.route('/admin/hire_trainer', methods=['GET', 'POST'])
@admin_required
def hire_trainer():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''), 32)
        password = request.form.get('password', '')
        full_name = sanitize_input(request.form.get('full_name', ''), 100)

        uid, err = create_user(username, password, full_name, ROLE_TRAINER)
        if err:
            log_event("HIRE_TRAINER_FAILED", f"Отклонён найм '{username}': {err}")
            flash(err, "danger")
            return render_template('hire_trainer.html')

        log_event("TRAINER_HIRED", f"Администратор зарегистрировал тренера {full_name} ({username})")
        flash(f"Тренер '{full_name}' успешно нанят!", "success")
        return redirect(url_for('index'))

    return render_template('hire_trainer.html')


@app.route('/admin/reports')
@admin_required
def reports():
    """Финансовый отчёт: выручка и востребованность услуг за период."""
    today = date.today()
    default_from = (today - timedelta(days=30)).isoformat()
    default_to = today.isoformat()

    date_from = request.args.get('from', default_from)
    date_to = request.args.get('to', default_to)
    service_filter = request.args.get('service', type=int)

    try:
        date.fromisoformat(date_from)
        date.fromisoformat(date_to)
    except ValueError:
        flash("Некорректная дата в фильтре.", "warning")
        date_from, date_to = default_from, default_to

    if date_from > date_to:
        date_from, date_to = date_to, date_from

    rows = financial_report(date_from, date_to, service_filter)
    summary = report_summary(rows)
    services = execute_query("SELECT id, title FROM services ORDER BY title")

    return render_template('reports.html',
                           rows=rows, summary=summary, services=services,
                           date_from=date_from, date_to=date_to,
                           service_filter=service_filter)


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
#  ТРЕНЕР
# ============================================================

@app.route('/trainer/bookings')
@trainer_required
def trainer_bookings():
    bookings = execute_query('''
        SELECT b.id, u.full_name as client_name, s.title as service_title,
               b.booking_date, b.status, b.created_at
        FROM bookings b
        JOIN users u ON b.client_id = u.id
        JOIN services s ON b.service_id = s.id
        ORDER BY CASE WHEN b.status = ? THEN 0 ELSE 1 END, b.created_at DESC
    ''', (ST_PENDING,))
    return render_template('trainer_bookings.html', bookings=bookings)


@app.route('/trainer/booking/<int:booking_id>/<action>', methods=['POST'])
@trainer_required
def process_booking(booking_id, action):
    if action not in ('accept', 'reject'):
        flash("Недопустимое действие.", "danger")
        return redirect(url_for('trainer_bookings'))

    new_status = ST_ACCEPTED if action == 'accept' else ST_REJECTED
    changed = execute_write(
        "UPDATE bookings SET status = ? WHERE id = ? AND status = ?",
        (new_status, booking_id, ST_PENDING))
    if not changed:
        flash("Заявка не найдена или уже обработана.", "warning")
        return redirect(url_for('trainer_bookings'))

    status_text = "принята" if action == 'accept' else "отклонена"
    log_event("BOOKING_PROCESSED", f"Тренер {session['username']} изменил статус заявки #{booking_id} на {new_status}")
    flash(f"Заявка #{booking_id} {status_text}.", "info")
    return redirect(url_for('trainer_bookings'))


# ============================================================
#  КЛИЕНТ
# ============================================================

@app.route('/book_service/<int:service_id>', methods=['POST'])
@client_required
@rate_limit('book', max_calls=30, window=3600, per_user=True)
def book_service(service_id):
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
    if booking_date > today + timedelta(days=Config.MAX_BOOKING_DAYS_AHEAD):
        flash("Запись возможна не более чем на год вперёд.", "warning")
        return redirect(url_for('index'))

    # Атомарно: проверка лимита + вставка в одной транзакции (BEGIN IMMEDIATE)
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        active = db.execute(
            "SELECT COUNT(*) AS c FROM bookings WHERE client_id = ? AND status = ?",
            (session['user_id'], ST_PENDING),
        ).fetchone()['c']
        if active >= Config.MAX_ACTIVE_BOOKINGS:
            db.rollback()
            flash("Слишком много заявок на рассмотрении. Дождитесь ответа тренера.", "warning")
            return redirect(url_for('my_bookings'))

        db.execute(
            "INSERT INTO bookings (client_id, service_id, booking_date, status) VALUES (?, ?, ?, ?)",
            (session['user_id'], service_id, booking_date.isoformat(), ST_PENDING),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        log_event("BOOKING_DUPLICATE",
                  f"Клиент {session['username']} пытался создать дубль на услугу #{service_id}")
        flash("У вас уже есть активная заявка на эту услугу на выбранную дату.", "warning")
        return redirect(url_for('my_bookings'))
    except Exception:
        db.rollback()
        raise

    log_event("BOOKING_SUBMITTED", f"Клиент {session['username']} создал заявку на услугу #{service_id}")
    flash("Заявка успешно отправлена! Ожидайте подтверждения тренера.", "success")
    return redirect(url_for('my_bookings'))


@app.route('/my_bookings')
@client_required
def my_bookings():
    status_filter = request.args.get('status', 'all')
    allowed = {'all', ST_PENDING, ST_ACCEPTED, ST_REJECTED, ST_CANCELLED}
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
    booking = execute_query(
        "SELECT id, status, booking_date FROM bookings WHERE id = ? AND client_id = ?",
        (booking_id, session['user_id']), one=True)

    if not booking:
        flash("Запись не найдена.", "warning")
        return redirect(url_for('my_bookings'))
    if booking['status'] == ST_CANCELLED:
        flash("Эта запись уже отменена.", "info")
        return redirect(url_for('my_bookings'))
    if booking['status'] == ST_REJECTED:
        flash("Отклонённые заявки нельзя отменить.", "info")
        return redirect(url_for('my_bookings'))

    changed = execute_write(
        "UPDATE bookings SET status = ? WHERE id = ? AND client_id = ? AND status IN (?, ?)",
        (ST_CANCELLED, booking_id, session['user_id'], ST_PENDING, ST_ACCEPTED))

    if not changed:
        flash("Не удалось отменить запись. Возможно, её статус уже изменился.", "warning")
        return redirect(url_for('my_bookings'))

    log_event("BOOKING_CANCELLED",
              f"Клиент {session['username']} отменил заявку #{booking_id} (дата: {booking['booking_date']})")
    flash(f"Запись на {booking['booking_date']} отменена.", "success")
    return redirect(url_for('my_bookings'))


# ============================================================
#  ОБРАБОТКА ОШИБОК
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


if __name__ == '__main__':
    host, debug = Config.HOST, Config.DEBUG
    if debug and host not in ('127.0.0.1', 'localhost', '::1'):
        print("[SECURITY] Режим отладки отключён: он недопустим при доступе из сети.")
        debug = False

    if Config.BACKUP_ENABLED and (not debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true'):
        from backup import start_backup_thread
        start_backup_thread()

    app.run(host=host, port=Config.PORT, debug=debug)