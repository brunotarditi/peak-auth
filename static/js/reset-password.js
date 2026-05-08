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
        Swal.fire({
            title: 'Atención',
            text: 'Por favor, complete todos los campos requeridos.',
            icon: 'warning',
            confirmButtonColor: '#4f46e5'
        });
        return;
    }

    if (password !== confirm) {
        Swal.fire({
            title: 'Error',
            text: 'Las contraseñas no coinciden.',
            icon: 'error',
            confirmButtonColor: '#4f46e5'
        });
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
            await Swal.fire({
                title: '¡Cuenta Activada!',
                text: text,
                icon: 'success',
                confirmButtonColor: '#4f46e5',
                timer: 3000
            });
            window.location.href = "/admin/login";
        } else {
            throw new Error(text || 'Ocurrió un error al procesar la solicitud');
        }
    } catch (err) {
        Swal.fire({
            title: 'Error',
            text: err.message,
            icon: 'error',
            confirmButtonColor: '#4f46e5'
        });
    } finally {
        submitBtn.disabled = false;
    }
}