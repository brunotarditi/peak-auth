/**
 * Muestra una notificación visual tipo toast.
 * @param {string} message 
 * @param {string} type - 'success', 'error', 'warning'
 * @param {number} duration - Tiempo en ms
 */
function showToast(message, type = 'success', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const typeConfigs = {
        success: {
            classes: 'toast-success',
            icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>'
        },
        error: {
            classes: 'toast-error',
            icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
        },
        warning: {
            classes: 'toast-warning',
            icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>'
        }
    };

    const config = typeConfigs[type] || typeConfigs.success;
    const toast = document.createElement('div');

    toast.className = `toast animate-slide-in-right ${config.classes}`;
    toast.innerHTML = `
        <div class="toast-icon">${config.icon}</div>
        <div class="toast-message">${message}</div>
        <button onclick="this.parentElement.remove()" class="toast-close">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 500);
    }, duration);
}

/**
 * Copia texto al portapapeles usando la API moderna.
 * @param {string} text 
 * @param {HTMLElement} btn 
 */
async function copyToClipboard(text, btn) {
    try {
        await navigator.clipboard.writeText(text);

        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
        showToast('Copiado con éxito', 'success', 2000);

        setTimeout(() => {
            btn.innerHTML = originalHTML;
        }, 2000);
    } catch (err) {
        console.error('Error al copiar:', err);
        showToast('Error al acceder al portapapeles', 'error');
    }
}


/**
 * Diálogo de confirmación premium estilo Peak Auth.
 * Devuelve true si el usuario confirma, false si cancela.
 * @param {object} options
 * @param {string} options.title - Título principal
 * @param {string} options.text - Descripción
 * @param {string} options.confirmText - Texto del botón de confirmar
 * @param {string} options.type - 'danger' | 'warning' | 'info'
 * @returns {Promise<boolean>}
 */
async function peakConfirm({ title, text, confirmText = 'Confirmar', type = 'danger' }) {
    const palette = window.PeakPalette || { error: '#b91c1c', warning: '#e5e843', secondary: '#3075ad' };
    
    const colorMap = {
        danger: { confirm: palette.error, iconColor: palette.error },
        warning: { confirm: palette.warning, iconColor: palette.warning },
        info: { confirm: palette.secondary, iconColor: palette.secondary }
    };
    const colors = colorMap[type] || colorMap.danger;

    const isDark = document.documentElement.classList.contains('dark');
    const background = isDark ? '#1e293b' : '#fff';
    const color = isDark ? '#f8fafc' : '#0f172a';

    const result = await Swal.fire({
        title: title,
        text: text,
        icon: type === 'danger' ? 'warning' : type,
        showCancelButton: true,
        confirmButtonText: confirmText,
        cancelButtonText: 'Cancelar',
        confirmButtonColor: colors.confirm,
        cancelButtonColor: '#64748b',
        iconColor: colors.iconColor,
        background: background,
        color: color,
        reverseButtons: true,
        customClass: {
            popup: 'rounded-3xl',
            confirmButton: 'rounded-xl font-bold',
            cancelButton: 'rounded-xl font-bold'
        }
    });

    return result.isConfirmed;
}

/**
 * Alerta premium para mostrar errores o información.
 * @param {string} title
 * @param {string} text
 * @param {string} icon - 'error' | 'success' | 'info' | 'warning'
 */
function peakAlert(title, text, icon = 'error') {
    const colorMap = {
        error: '#e11d48',
        success: '#10b981',
        info: '#6366f1',
        warning: '#f59e0b'
    };
    const isDark = document.documentElement.classList.contains('dark');
    const background = isDark ? '#1e293b' : '#fff';
    const color = isDark ? '#f8fafc' : '#0f172a';

    Swal.fire({
        title: title,
        text: text,
        icon: icon,
        confirmButtonText: 'Entendido',
        confirmButtonColor: colorMap[icon] || '#6366f1',
        background: background,
        color: color,
        customClass: {
            popup: 'rounded-3xl',
            confirmButton: 'rounded-xl font-bold'
        }
    });
}

/**
 * Alternar visibilidad de contraseña en el campo de login
 * @param {string} fieldId - ID del campo input tipo password
 */
function toggleLoginPassword(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;

    input.type = input.type === 'password' ? 'text' : 'password';
}
