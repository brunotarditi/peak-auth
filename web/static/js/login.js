/**
 * Login.js - Gestión de la interfaz de acceso al panel administrativo.
 */

window.addEventListener('load', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const errorMsg = urlParams.get('error');

    if (errorMsg) {
        const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };
        Swal.fire({
            title: 'Error de Acceso',
            text: errorMsg,
            icon: 'error',
            confirmButtonColor: window.PeakPalette ? window.PeakPalette.error : '#b91c1c',
            confirmButtonText: 'Entendido',
            background: themeConfig.background,
            color: themeConfig.color
        });

        window.history.replaceState({}, document.title, window.location.pathname);
    }
});


