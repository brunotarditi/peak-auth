/**
 * app.js - Core de la lógica administrativa de Peak Auth.
 * Gestiona el guardado de políticas de aplicación (Registro, Password, Sesión, Authz)
 * y elementos comunes de la interfaz del dashboard.
 */

// --- Gestión de Modales ---

function openRevokeModal() {
    document.getElementById('revokeModal').classList.remove('hidden');
}

function closeRevokeModal() {
    document.getElementById('revokeModal').classList.add('hidden');
}


// app_new.html

const form = document.getElementById("appForm");
const submitBtn = document.getElementById("submitBtn");

if (!form) return;

const isEdit = form.dataset.edit === "true";

// habilitar botón al cambiar algo
form.addEventListener("input", () => {
    if (submitBtn) submitBtn.disabled = false;
});

// lógica de edición
if (isEdit) {
    form.addEventListener("submit", (event) => {
        const checkbox = document.getElementById("is_active");

        if (!checkbox.checked) {
            event.preventDefault();

            peakConfirm({
                title: "¿Desactivar y Eliminar aplicación?",
                text: "La aplicación se desactivará...",
                confirmText: "Sí, eliminar",
                type: "danger"
            }).then((confirmed) => {
                if (confirmed) {
                    form.submit();
                } else {
                    checkbox.checked = true;
                }
            });
        }
    });
}

// --- Notificaciones (Toasts) ---

/**
 * Muestra un mensaje temporal en la parte inferior de la pantalla.
 * @param {string} msg - Mensaje a mostrar.
 */
function showToast(msg) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    document.getElementById('toast-msg').innerText = msg;
    toast.classList.remove('translate-y-20', 'opacity-0');
    setTimeout(() => {
        toast.classList.add('translate-y-20', 'opacity-0');
    }, 3000);
}

// Toggle Edit Mode
function toggleEdit(code, colorClass) {
    const fs = document.getElementById('fs_' + code);
    const btn = document.getElementById('btn_edit_' + code);

    if (fs.hasAttribute('disabled')) {
        // Habilitar
        fs.removeAttribute('disabled');
        fs.classList.remove('opacity-80', 'cursor-not-allowed');
        // Cambiar icono a palomita/completado
        btn.innerHTML = `<span class="text-[9px] font-black uppercase tracking-widest hidden group-hover/btn:block">Listo</span>
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
        btn.title = "Bloquear edición";
        btn.classList.add('text-' + colorClass + '-600', 'bg-' + colorClass + '-50', 'dark:bg-' + colorClass + '-900/30');
    } else {
        // Deshabilitar (Ya guardó o quiere salir)
        fs.setAttribute('disabled', 'disabled');
        fs.classList.add('opacity-80', 'cursor-not-allowed');
        // Regresar icono a lápiz
        btn.innerHTML = `<span class="text-[9px] font-black uppercase tracking-widest hidden group-hover/btn:block text-${colorClass}-600">Editar</span>
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>`;
        btn.title = "Desbloquear para editar";
        btn.classList.remove('text-' + colorClass + '-600', 'bg-' + colorClass + '-50', 'dark:bg-' + colorClass + '-900/30');
    }
}

// Helpers visuales
function toggleUI(checkbox, wrapperId) {
    const wrapper = document.getElementById(wrapperId);
    const circle = wrapper.querySelector('div');
    if (checkbox.checked) {
        wrapper.classList.remove('bg-slate-300', 'dark:bg-slate-600');
        wrapper.classList.add('bg-emerald-500');
        circle.classList.add('translate-x-3');
    } else {
        wrapper.classList.remove('bg-emerald-500');
        wrapper.classList.add('bg-slate-300', 'dark:bg-slate-600');
        circle.classList.remove('translate-x-3');
    }
}

function togglePill(checkbox, labelId, color) {
    const label = document.getElementById(labelId);
    if (checkbox.checked) {
        label.className = `text-center p-2 rounded-xl cursor-pointer transition-colors bg-${color}-50 dark:bg-${color}-900/20 text-${color}-600 dark:text-${color}-400`;
    } else {
        label.className = `text-center p-2 rounded-xl cursor-pointer transition-colors bg-slate-50 dark:bg-slate-800 text-slate-400`;
    }
}

// Lógica de Guardado API
async function saveRule(code, data) {
    if (!window.appID) {
        console.error("window.appID no definido");
        return;
    }
    try {
        const response = await fetch(`/admin/apps/${window.appID}/rules/${code}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            let errMsg = 'Error al guardar políticas';
            try {
                const errData = await response.json();
                errMsg = errData.error || errMsg;
            } catch (e) { }
            throw new Error(errMsg);
        }

        showToast('Guardado automáticamente');
    } catch (err) {
        console.error(err);
        peakAlert('Error', err.message, 'error');
    }
}

// Funciones expuestas a los onchange
function updateRegistration() {
    saveRule('REGISTRATION_POLICY', {
        mode: document.getElementById('reg_mode').value,
        default_role: document.getElementById('reg_default_role').value,
        require_email_verification: document.getElementById('reg_require_email_verification').checked
    });
}

function updatePassword() {
    saveRule('PWD_POLICY', {
        min_length: parseInt(document.getElementById('pwd_min_length').value) || 8,
        require_uppercase: document.getElementById('pwd_require_uppercase').checked,
        require_numbers: document.getElementById('pwd_require_numbers').checked,
        require_symbols: document.getElementById('pwd_require_symbols').checked
    });
}

function updateSession() {
    saveRule('SESSION_POLICY', {
        token_expiration_minutes: parseInt(document.getElementById('session_expiration').value) || 1440,
        max_failed_logins: parseInt(document.getElementById('session_max_failed').value) || 5
    });
}

function updateAuthz() {
    const enabled = document.getElementById('authz_enable_roles').checked;

    // update label on the fly
    const desc = document.getElementById('authz_description');
    if (enabled) {
        desc.innerText = "Los accesos están supeditados a los roles y premisos asignados.";
    } else {
        desc.innerText = "Sistema plano. Cualquier usuario autenticado tiene acceso total.";
    }

    saveRule('AUTHZ_POLICY', {
        enable_roles: enabled
    });
}

// Lógica de Políticas Personalizadas
async function addCustomRule() {
    const { value: code } = await Swal.fire({
        title: 'Nueva Política',
        input: 'text',
        inputLabel: 'Identificador de la política (ej. EXTRA_POLICY)',
        inputPlaceholder: 'NOMBRE_POLICY',
        showCancelButton: true,
        confirmButtonText: 'Crear',
        cancelButtonText: 'Cancelar',
        confirmButtonColor: '#6366f1',
        cancelButtonColor: '#64748b',
        customClass: { popup: 'rounded-3xl', confirmButton: 'rounded-xl font-bold', cancelButton: 'rounded-xl font-bold' },
        inputValidator: (value) => {
            if (!value || value.trim() === '') return 'Debes ingresar un identificador';
        }
    });
    if (!code) return;
    try {
        const response = await fetch(`/admin/apps/${window.appID}/rules/${code.trim().toUpperCase()}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ "enabled": true })
        });
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(errText || 'Error al crear política');
        }
        window.location.reload();
    } catch (err) {
        peakAlert('Error', err.message, 'error');
    }
}

async function deleteRule(code) {
    const confirmed = await peakConfirm({
        title: `¿Eliminar política "${code}"?`,
        text: 'Esta acción desactivará la política de forma permanente.',
        confirmText: 'Sí, eliminar',
        type: 'danger'
    });
    if (!confirmed) return;
    try {
        const response = await fetch(`/admin/apps/${window.appID}/rules/${code}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Error al eliminar');
        window.location.reload();
    } catch (err) {
        peakAlert('Error', err.message, 'error');
    }
}

function updateGenericRule(code) {
    try {
        const raw = document.getElementById('val_' + code).value;
        const data = JSON.parse(raw);
        saveRule(code, data);
    } catch (err) {
        peakAlert('JSON Inválido', 'El valor debe ser un objeto JSON válido.\nEjemplo: {"key": "value"}', 'warning');
        return;
    }
}

// Confirmación premium para eliminar la app
async function confirmDeleteApp() {
    const confirmed = await peakConfirm({
        title: '¿Eliminar esta aplicación?',
        text: 'ATENCIÓN: Esta acción es irreversible. La aplicación y todos sus datos serán eliminados de la vista del panel de forma permanente.',
        confirmText: 'Sí, eliminar definitivamente',
        type: 'danger'
    });
    if (confirmed) {
        document.getElementById('deleteAppForm').submit();
    }
}


async function handleReset(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('button[type="submit"]');
    btn.disabled = true;

    const body = new URLSearchParams();
    body.append('token', document.getElementById('reset_token').value);
    body.append('password', document.getElementById('password_field').value);
    body.append('confirm_password', document.getElementById('confirm_password_field').value);

    try {
        const response = await fetch('/api/v1/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        });
        const text = await response.text();

        if (response.ok) {
            await Swal.fire({
                title: 'Éxito',
                text: text,
                icon: 'success',
                confirmButtonColor: '#4f46e5'
            });
            form.reset();
            // Como el usuario activó su cuenta, lo regresamos al login o cerramos la vista
            window.location.href = "/admin/login";
        } else {
            Swal.fire({
                title: 'Error',
                text: text,
                icon: 'error',
                confirmButtonColor: '#4f46e5'
            });
        }
    } catch (err) {
        Swal.fire({
            title: 'Error de conexión',
            text: 'No se pudo conectar con el servidor',
            icon: 'error',
            confirmButtonColor: '#4f46e5'
        });
    } finally {
        btn.disabled = false;
    }
}

