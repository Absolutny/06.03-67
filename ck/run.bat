@echo off
chcp 65001 > nul
title Спортивный Комплекс - Сервер
cd /d "%~dp0"
echo ===================================================
echo   Запуск веб-приложения Спортивный Комплекс
echo ===================================================
echo.

:: Поиск Python: py-лаунчер, python из PATH, либо прежний путь установки
set "PYEXE="
where py >nul 2>nul && set "PYEXE=py"
if not defined PYEXE where python >nul 2>nul && set "PYEXE=python"
if not defined PYEXE if exist "C:\Program Files\Python313\python.exe" set "PYEXE=C:\Program Files\Python313\python.exe"
if not defined PYEXE (
    echo Python не найден. Установите Python 3.10+ с python.org
    pause
    exit /b 1
)

:: 1. Установка зависимостей
"%PYEXE%" -m pip install -r requirements.txt -q

:: 2. Инициализация БД. Флаг --demo создаёт тестовые аккаунты (admin/trainer/client)
::    ТОЛЬКО ДЛЯ РАЗРАБОТКИ. В боевом режиме уберите --demo: администратор получит случайный пароль.
"%PYEXE%" init_db.py --demo

:: 3. Открытие сайта в браузере
start "" http://127.0.0.1:5000/

:: 4. Запуск веб-сервера (по умолчанию только локальный доступ, отладка выключена)
"%PYEXE%" app.py

pause
