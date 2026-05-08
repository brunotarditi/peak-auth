/**
 * Abre el modal de revocación
 */
function openRevokeModal() {
    document.getElementById('revokeModal').classList.remove('hidden');
}

/**
 * Cierra el modal de revocación
 */
function closeRevokeModal() {
    document.getElementById('revokeModal').classList.add('hidden');
}

/**
 * Event listener para el DOM
 */
document.addEventListener("DOMContentLoaded", () => {
    const openRevokeBtn = document.getElementById("openRevokeModalBtn");
    const closeRevokeBtn = document.getElementById("closeRevokeModalBtn");
    const revokeBackdrop = document.getElementById("revokeModalBackdrop");

    if (openRevokeBtn) {
        openRevokeBtn.addEventListener("click", openRevokeModal);
    }

    if (closeRevokeBtn) {
        closeRevokeBtn.addEventListener("click", closeRevokeModal);
    }

    if (revokeBackdrop) {
        revokeBackdrop.addEventListener("click", closeRevokeModal);
    }

    const form = document.getElementById("appForm");
    const submitBtn = document.getElementById("submitBtn");

    if (!form) return;

    const isEdit = form.dataset.edit === "true";

    form.addEventListener("input", () => {
        if (submitBtn) submitBtn.disabled = false;
    });

    if (isEdit) {
        form.addEventListener("submit", (event) => {
            const checkbox = document.getElementById("is_active");

            if (checkbox && !checkbox.checked) {
                event.preventDefault();

                peakConfirm({
                    title: "¿Desactivar y Eliminar aplicación?",
                    text: "La aplicación se desactivará...",
                    confirmText: "Sí, eliminar",
                    type: "danger"
                }).then((confirmed) => {
                    if (confirmed) {
                        form.submit();
                    } else if (checkbox) {
                        checkbox.checked = true;
                    }
                });
            }
        });
    }

    const checkbox = document.getElementById("is_active");

    if (checkbox && checkbox.dataset.locked === "true") {
        checkbox.addEventListener("click", (e) => {
            e.preventDefault();
            peakAlert("Denegado", "...", "error");
        });
    }
});



/**
 * Cambia el estado de edición de un campo
 * @param {*} code 
 * @param {*} colorClass 
 */
function toggleEdit(code, colorClass) {
    const fs = document.getElementById('fs_' + code);
    const btn = document.getElementById('btn_edit_' + code);

    if (fs.hasAttribute('disabled')) {
        // Habilitar
        fs.removeAttribute('disabled');
        fs.classList.remove('opacity-80', 'cursor-not-allowed');
        // Cambiar icono a palomita/completado
        btn.innerHTML = `<span class="text-[9px] font-black uppercase tracking-widest hidden group-hover/btn:block text-slate-700 dark:text-slate-300">Listo</span>
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
        btn.title = "Bloquear edición";
    } else {
        // Deshabilitar (Ya guardó o quiere salir)
        fs.setAttribute('disabled', 'disabled');
        fs.classList.add('opacity-80', 'cursor-not-allowed');
        // Regresar icono a lápiz
        btn.innerHTML = `<span class="text-[9px] font-black uppercase tracking-widest hidden group-hover/btn:block text-slate-700 dark:text-slate-300">Editar</span>
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>`;
        btn.title = "Desbloquear para editar";
    }

    btn.classList.toggle('policy-card-edit-active', !fs.hasAttribute('disabled'));
}

/**
 * Cambia el color del wrapper
 * @param {*} checkbox 
 * @param {*} wrapperId 
 */
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

/**
 * Cambia el color de la píldora
 * @param {*} checkbox 
 * @param {*} labelId 
 * @param {*} color 
 */
function togglePill(checkbox, labelId, color) {
    const label = document.getElementById(labelId);
    if (checkbox.checked) {
        label.className = `text-center p-2 rounded-xl cursor-pointer transition-colors bg-${color}-50 dark:bg-${color}-900/20 text-${color}-600 dark:text-${color}-400`;
    } else {
        label.className = `text-center p-2 rounded-xl cursor-pointer transition-colors bg-slate-50 dark:bg-slate-800 text-slate-400`;
    }
}

/**
 * Confirmación para eliminar la app
 */
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

/**
 * Guarda una regla
 * @param {*} code 
 * @param {*} data 
 * @returns 
 */
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

/**
 * Actualiza la política de registro
 */
function updateRegistration() {
    saveRule('REGISTRATION_POLICY', {
        mode: document.getElementById('reg_mode').value,
        default_role: document.getElementById('reg_default_role').value,
        require_email_verification: document.getElementById('reg_require_email_verification').checked
    });
}

/**
 * Actualiza la política de contraseñas
 */
function updatePassword() {
    saveRule('PWD_POLICY', {
        min_length: parseInt(document.getElementById('pwd_min_length').value) || 8,
        require_uppercase: document.getElementById('pwd_require_uppercase').checked,
        require_numbers: document.getElementById('pwd_require_numbers').checked,
        require_symbols: document.getElementById('pwd_require_symbols').checked
    });
}

/**
 * Actualiza la política de sesiones
 */
function updateSession() {
    saveRule('SESSION_POLICY', {
        token_expiration_minutes: parseInt(document.getElementById('session_expiration').value) || 1440,
        max_failed_logins: parseInt(document.getElementById('session_max_failed').value) || 5
    });
}

/**
 * Actualiza la política de autorización
 */
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

