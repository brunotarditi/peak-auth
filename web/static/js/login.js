(() => {
    'use strict';

    /**
     * Login.js - Gestión de la interfaz de acceso al panel administrativo.
     */
    window.addEventListener('load', () => {
        const urlParams = new URLSearchParams(window.location.search);
        const errorMsg = urlParams.get('error');

        if (errorMsg) {
            PeakModal.fire({
                title: 'Error de acceso',
                text: errorMsg,
                icon: 'error',
                confirmButtonText: 'Entendido'
            });

            window.history.replaceState({}, document.title, window.location.pathname);
        }
    });
})();


