/**
 * config.js - Configuración global y gestión de preferencias.
 * Controla principalmente el modo oscuro y parámetros compartidos.
 */

window.PeakPalette = {
    primary: '#083d69',
    secondary: '#3075ad',
    warning: '#e5e843',
    success: '#10b981',
    error: '#b91c1c',
    cancel: '#64748b',
    light: {
        background: '#ffffff',
        text: '#0f172a'
    },
    dark: {
        background: '#1e293b',
        text: '#f8fafc'
    }
};

/**
 * Retorna la configuración de fondo y texto base (útil para modales como SweetAlert2)
 * evaluando si el modo oscuro está activo actualmente.
 */
window.getPeakThemeConfig = function() {
    const isDark = document.documentElement.classList.contains('dark');
    const theme = isDark ? window.PeakPalette.dark : window.PeakPalette.light;
    return {
        background: theme.background,
        color: theme.text
    };
};

function shouldUseDarkTheme() {
    const savedTheme = localStorage.getItem('darkMode');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    return savedTheme === 'true' || (savedTheme === null && prefersDark);
}

function applyThemeClass(isDark) {
    document.documentElement.classList.toggle('dark', isDark);
}

/**
 * Cambia entre modo claro y oscuro, persistiendo la preferencia en localStorage.
 * Toggles between light and dark mode, persisting the preference in localStorage.
 */
function toggleDarkMode() {
    const isDark = !document.documentElement.classList.contains('dark');
    applyThemeClass(isDark);
    localStorage.setItem('darkMode', isDark);

    updateThemeIcons(isDark);
}

/**
 * Actualiza los iconos del tema.
 * Updates the theme icons.
 */
function updateThemeIcons(isDark) {
    const moon = document.getElementById('moon-icon');
    const sun = document.getElementById('sun-icon');

    if (!moon || !sun) {
        return;
    }

    moon.classList.toggle('hidden', isDark);
    sun.classList.toggle('hidden', !isDark);
}

/**
 * Aplica la clase de tema al documento.
 * Applies the theme class to the document.
 */
applyThemeClass(shouldUseDarkTheme());

/**
 * Actualiza los iconos del tema al cargar el documento.
 * Updates the theme icons when the document is loaded.
 */
document.addEventListener('DOMContentLoaded', () => {
    updateThemeIcons(document.documentElement.classList.contains('dark'));
});


/** ===========================================================================
 * Protección CSRF (double-submit cookie)
 * - Lee la cookie csrf_token (no HttpOnly) emitida por el servidor.
 * - Reenvía su valor en el header X-CSRF-Token en toda petición fetch mutadora
 *   del mismo origen.
 * - Inyecta un campo oculto csrf_token en los formularios POST/PUT/DELETE para
 *   los envíos tradicionales (no-AJAX).
 * =========================================================================== */
(function () {
    function getCSRFToken() {
        const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    // Exponer un helper global por si algún script lo necesita explícitamente.
    window.getCSRFToken = getCSRFToken;

    // 1. Parchear fetch para adjuntar el header CSRF en métodos mutadores same-origin.
    const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
        init = init || {};
        const method = (init.method || (typeof input === 'object' && input.method) || 'GET').toUpperCase();

        let sameOrigin = true;
        try {
            const url = new URL((typeof input === 'string' ? input : input.url), window.location.origin);
            sameOrigin = url.origin === window.location.origin;
        } catch (e) {
            sameOrigin = true; // rutas relativas
        }

        if (!SAFE_METHODS.includes(method) && sameOrigin) {
            const token = getCSRFToken();
            const headers = new Headers(init.headers || (typeof input === 'object' ? input.headers : undefined) || {});
            if (token && !headers.has('X-CSRF-Token')) {
                headers.set('X-CSRF-Token', token);
            }
            init.headers = headers;
            if (init.credentials === undefined) {
                init.credentials = 'same-origin';
            }
        }
        return originalFetch.call(this, input, init);
    };

    // 2. Inyectar el token como campo oculto en formularios mutadores.
    function injectFormToken(form) {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (SAFE_METHODS.includes(method)) return;
        if (form.querySelector('input[name="csrf_token"]')) return;
        const token = getCSRFToken();
        if (!token) return;
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = token;
        form.appendChild(input);
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('form').forEach(injectFormToken);
    });

    // Refrescar el token justo antes de enviar (por si la cookie cambió).
    document.addEventListener('submit', (e) => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement)) return;
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (SAFE_METHODS.includes(method)) return;
        const token = getCSRFToken();
        if (!token) return;
        let input = form.querySelector('input[name="csrf_token"]');
        if (!input) {
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'csrf_token';
            form.appendChild(input);
        }
        input.value = token;
    }, true);
})();


