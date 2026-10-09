(() => {
    'use strict';

    document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('resetForm');
        if (form) {
            form.addEventListener('submit', handleReset);
        }
    });

    /**
     * Maneja el restablecimiento de contraseña y activación de cuenta.
     */
    async function handleReset(e) {
        e.preventDefault();
        
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        const token = document.getElementById('reset_token')?.value;
        const password = document.getElementById('password_field')?.value;
        const confirm = document.getElementById('confirm_password_field')?.value;

        if (!token || !password) {
            peakAlert('Atención', 'Por favor, complete todos los campos requeridos.', 'warning');
            return;
        }

        if (password !== confirm) {
            peakAlert('Error', 'Las contraseñas no coinciden.', 'error');
            return;
        }

        submitBtn.disabled = true;

        const body = new URLSearchParams();
        body.append('token', token);
        body.append('password', password);
        body.append('confirm_password', confirm);

        try {
            const response = await fetch('/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body
            });
            
            const text = await response.text();

            if (response.ok) {
                const params = new URLSearchParams(window.location.search);
                const isRequired = params.get('required') === 'true' || params.get('expired') === 'true';
                PeakModal.fire({
                    title: isRequired ? '¡Contraseña actualizada!' : '¡Cuenta activada!',
                    text: text,
                    icon: 'success',
                    timer: 2500,
                    showConfirmButton: false
                }).then(() => {
                    if (params.get('client_id')) {
                        params.delete('required');
                        params.delete('expired');
                        params.delete('token');
                        window.location.href = "/oauth/login?" + params.toString();
                    } else {
                        window.location.href = "/admin/login";
                    }
                });
            } else {
                throw new Error(text || 'Ocurrió un error al procesar la solicitud');
            }
        } catch (err) {
            peakAlert('Error', err.message, 'error');
        } finally {
            submitBtn.disabled = false;
        }
    }

    window.handleReset = handleReset;
})();
