// Dark Mode Support
function toggleDarkMode() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', isDark);
    updateThemeIcons(isDark);
}

function updateThemeIcons(isDark) {
    const moon = document.getElementById('moon-icon');
    const sun = document.getElementById('sun-icon');
    if (moon && sun) {
        if (isDark) {
            moon.classList.add('hidden');
            sun.classList.remove('hidden');
        } else {
            moon.classList.remove('hidden');
            sun.classList.add('hidden');
        }
    }
}

// Initialize theme on load
(function () {
    const savedTheme = localStorage.getItem('darkMode');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'true' || (savedTheme === null && prefersDark)) {
        document.documentElement.classList.add('dark');
        // We can't update icons yet as DOM might not be ready, 
        // will do on DOMContentLoaded
    }
})();

document.addEventListener('DOMContentLoaded', () => {
    const isDark = document.documentElement.classList.contains('dark');
    updateThemeIcons(isDark);
});

function showToast(message, type = 'success') {
    console.log(`Showing toast: ${message} (${type})`);
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        // Ensure it's fixed and high z-index
        container.style.position = 'fixed';
        container.style.bottom = '2rem';
        container.style.right = '2rem';
        container.style.zIndex = '10000';
        container.style.display = 'flex';
        container.style.flexDirection = 'column';
        container.style.gap = '1rem';
        container.style.alignItems = 'flex-end';
        container.style.pointerEvents = 'none';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const typeConfigs = {
        success: {
            bg: 'bg-emerald-50',
            border: 'border-emerald-100',
            text: 'text-emerald-800',
            icon: 'text-emerald-500',
            svg: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>'
        },
        error: {
            bg: 'bg-rose-50',
            border: 'border-rose-100',
            text: 'text-rose-800',
            icon: 'text-rose-500',
            svg: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
        },
        warning: {
            bg: 'bg-amber-50',
            border: 'border-amber-100',
            text: 'text-amber-800',
            icon: 'text-amber-500',
            svg: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>'
        }
    };

    const config = typeConfigs[type] || typeConfigs.success;

    toast.className = `flex items-center gap-4 px-6 py-4 ${config.bg} border ${config.border} ${config.text} rounded-2xl shadow-2xl shadow-slate-300/40 min-w-[320px] animate-slide-in-right pointer-events-auto transition-all duration-500`;
    toast.innerHTML = `
        <div class="${config.icon} shrink-0">${config.svg}</div>
        <div class="text-sm font-bold flex-grow pr-2">${message}</div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
    `;

    container.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

async function copyToClipboard(text, btn) {
    console.log('Copying to clipboard...');
    try {
        if (!navigator.clipboard) {
            // Fallback for non-https/older browsers
            const textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand("copy");
            document.body.removeChild(textArea);
        } else {
            await navigator.clipboard.writeText(text);
        }

        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
        showToast('Copiado al portapapeles', 'success');
        setTimeout(() => {
            btn.innerHTML = originalHTML;
        }, 2000);
    } catch (err) {
        console.error('Failed to copy: ', err);
        showToast('Error al copiar', 'error');
    }
}
