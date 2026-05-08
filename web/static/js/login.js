/**
 * Login.js - Gestión de la interfaz de acceso al panel administrativo.
 */

window.addEventListener('load', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const errorMsg = urlParams.get('error');

    if (errorMsg) {
        Swal.fire({
            title: 'Error de Acceso',
            text: errorMsg,
            icon: 'error',
            confirmButtonColor: '#4f46e5',
            confirmButtonText: 'Entendido',
            background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
            color: document.documentElement.classList.contains('dark') ? '#f1f5f9' : '#1e293b'
        });

        window.history.replaceState({}, document.title, window.location.pathname);
    }
});


