async function handleReset(e) {
            e.preventDefault();
            const token = document.getElementById('reset_token').value;
            const password = document.getElementById('password_field').value;
            const confirmPassword = document.getElementById('confirm_password_field').value;

            if (password !== confirmPassword) {
                Swal.fire({
                    icon: 'error',
                    title: 'Las contraseñas no coinciden',
                    text: 'Por favor, verifica e intenta de nuevo'
                });
                return;
            }

            try {
                const response = await fetch('/admin/password/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, password })
                });

                if (response.ok) {
                    Swal.fire({
                        icon: 'success',
                        title: '¡Contraseña establecida!',
                        text: 'Redirigiendo...',
                        showConfirmButton: false,
                        timer: 1500
                    }).then(() => {
                        window.location.href = '/admin/';
                    });
                } else {
                    const data = await response.json();
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: data.error || 'No se pudo establecer la contraseña'
                    });
                }
            } catch (error) {
                console.error(error);
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Error de conexión'
                });
            }
        }