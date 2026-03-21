/**
 * config.js - Configuración global y gestión de preferencias.
 * Controla principalmente el modo oscuro y parámetros compartidos.
 */

// Aplicar modo oscuro inmediatamente antes del renderizado del body para evitar parpadeos
// Apply dark mode immediately before body rendering to prevent flashes
if (localStorage.getItem('darkMode') === 'true' || (!localStorage.getItem('darkMode') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
}

/**
 * Cambia entre modo claro y oscuro, persistiendo la preferencia en localStorage.
 * Toggles between light and dark mode, persisting the preference in localStorage.
 */
function toggleDarkMode() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', isDark);
    
    // Actualizar iconos si existen
    // Update icons if they exist
    const moon = document.getElementById('moon-icon');
    const sun = document.getElementById('sun-icon');
    if(moon && sun) {
        if(isDark) {
            moon.classList.add('hidden');
            sun.classList.remove('hidden');
        } else {
            moon.classList.remove('hidden');
            sun.classList.add('hidden');
        }
    }
}

// Tailwind Configuration
if (typeof tailwind !== 'undefined') {
    tailwind.config = {
        darkMode: 'class',
        theme: {
            extend: {
                colors: {
                    dark: {
                        bg: '#0f172a',
                        card: '#1e293b',
                        border: '#334155'
                    }
                }
            }
        }
    };
}
