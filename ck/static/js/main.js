document.addEventListener('DOMContentLoaded', () => {

    // 1. Автоматическое ограничение даты (запрет выбора прошедших дат)
    const dateInputs = document.querySelectorAll('input[type="date"]');
    if (dateInputs.length > 0) {
        const today = new Date().toISOString().split('T')[0];
        dateInputs.forEach(input => {
            input.setAttribute('min', today);
        });
    }

    // 2. Автоскрытие всплывающих Flash-уведомлений через 4 секунды
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 500);
        }, 4000);
    });

    // 3. Подтверждение отклонения заявки тренером
    const rejectForms = document.querySelectorAll('form[action*="/reject"]');
    rejectForms.forEach(form => {
        form.addEventListener('submit', (e) => {
            if (!confirm('Вы уверены, что хотите отклонить эту заявку?')) {
                e.preventDefault();
            }
        });
    });

    // 4. Блокировка повторных нажатий на кнопки отправки форм
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            if (e.defaultPrevented) return; // отмена подтверждения — кнопку не блокируем
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.classList.contains('no-disable')) {
                setTimeout(() => {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Обработка...';
                }, 50);
            }
        });
    });

});
