/**
 * config.js - Configuración global y gestión de preferencias.
 * Controla principalmente el modo oscuro y parámetros compartidos.
 */

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


