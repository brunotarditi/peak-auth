/**
 * Maneja el reset de contraseña
 */
async function handleReset(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('button[type="submit"]');
    btn.disabled = true;

    const body = new URLSearchParams();
    body.append('token', document.getElementById('reset_token').value);
    body.append('password', document.getElementById('password_field').value);
    body.append('confirm_password', document.getElementById('confirm_password_field').value);

    try {
        const response = await fetch('/api/v1/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        });
        const text = await response.text();

        if (response.ok) {
            await Swal.fire({
                title: 'Éxito',
                text: text,
                icon: 'success',
                confirmButtonColor: '#4f46e5'
            });
            form.reset();
            // Como el usuario activó su cuenta, lo regresamos al login o cerramos la vista
            window.location.href = "/admin/login";
        } else {
            Swal.fire({
                title: 'Error',
                text: text,
                icon: 'error',
                confirmButtonColor: '#4f46e5'
            });
        }
    } catch (err) {
        Swal.fire({
            title: 'Error de conexión',
            text: 'No se pudo conectar con el servidor',
            icon: 'error',
            confirmButtonColor: '#4f46e5'
        });
    } finally {
        btn.disabled = false;
    }
}