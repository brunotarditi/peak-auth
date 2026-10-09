(() => {
    'use strict';

    const form = document.getElementById('authForm');
    if (!form) return;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const token = document.getElementById('token').value;
        const tokenError = document.getElementById('tokenError');
        if (!token) {
            tokenError.classList.remove('hidden');
            return;
        }

        tokenError.classList.add('hidden');
        const formData = new FormData(form);

        try {
            const response = await fetch('/setup/auth', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (response.ok && data.redirect) {
                window.location.href = data.redirect;
                return;
            }

            peakAlert('Error de autenticación', data.error || 'Token inválido', 'error');
        } catch (error) {
            peakAlert('Error de conexión', 'Error al autenticar. Por favor, intente nuevamente.', 'error');
        }
    });
})();
