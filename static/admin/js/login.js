/**
 * Login.js - Gestión de la interfaz de acceso al panel administrativo.
 * Se encarga de mostrar alertas de error desde la URL y manejar micro-interacciones.
 */

window.addEventListener('load', () => {
    // 1. Extraer errores de la URL (query params)
    const urlParams = new URLSearchParams(window.location.search);
    const errorMsg = urlParams.get('error');

    if (errorMsg) {
        // Mostrar SweetAlert2
        Swal.fire({
            title: 'Error de Acceso',
            text: errorMsg,
            icon: 'error',
            confirmButtonColor: '#4f46e5',
            confirmButtonText: 'Entendido',
            background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
            color: document.documentElement.classList.contains('dark') ? '#f1f5f9' : '#1e293b'
        });

        // Limpiar la URL después de mostrar el error para evitar re-disparos al recargar
        window.history.replaceState({}, document.title, window.location.pathname);
    }
});

/**
 * Alternar visibilidad de contraseña en el campo de login
 * @param {string} fieldId - ID del campo input tipo password
 */
function toggleLoginPassword(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    
    input.type = input.type === 'password' ? 'text' : 'password';
}
