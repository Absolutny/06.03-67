(function () {
    'use strict';

    // Единый механизм подтверждения форм: <form data-confirm="Текст...">
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement)) return;

        var msg = form.getAttribute('data-confirm');
        if (!msg) return;

        if (!window.confirm(msg)) {
            e.preventDefault();
            e.stopPropagation();
        }
    });

    // Автоскрытие flash-уведомлений через 6 секунд
    setTimeout(function () {
        document.querySelectorAll('.alert-dismissible').forEach(function (el) {
            if (window.bootstrap && bootstrap.Alert) {
                bootstrap.Alert.getOrCreateInstance(el).close();
            }
        });
    }, 6000);
})();