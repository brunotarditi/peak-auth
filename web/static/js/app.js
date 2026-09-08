(() => {
    'use strict';

    /**
     * Abre la confirmación para regenerar el secreto de la aplicación usando el modal nativo
     */
    async function openRevokeModal() {
        const confirmed = await peakConfirm({
            title: '¿Regenerar Secreto?',
            text: 'Esta acción invalidará el secreto actual de inmediato. Cualquier aplicación que use las credenciales antiguas dejará de autenticarse.',
            confirmText: 'Sí, Regenerar Ahora',
            type: 'danger'
        });

        if (confirmed) {
            const form = document.getElementById('revokeSecretForm');
            if (form) form.submit();
        }
    }

    /**
     * Confirmación para eliminar la app
     */
    async function confirmDeleteApp() {
        const confirmed = await peakConfirm({
            title: '¿Eliminar esta aplicación?',
            text: 'Atención: Esta acción es irreversible. La aplicación y todos sus datos serán eliminados de la vista del panel de forma permanente.',
            confirmText: 'Sí, eliminar definitivamente',
            type: 'danger'
        });
        if (confirmed) {
            const form = document.getElementById('deleteAppForm');
            if (form) form.submit();
        }
    }

    /**
     * Cambia el estado de edición de una sección de políticas
     * @param {string} code 
     */
    function toggleEdit(code) {
        const fs = document.getElementById('fs_' + code);
        const btn = document.getElementById('btn_edit_' + code);
        if (!fs || !btn) return;

        const isDisabled = fs.hasAttribute('disabled');
        if (isDisabled) {
            fs.removeAttribute('disabled');
            fs.style.opacity = '1';
            fs.style.cursor = 'default';
            btn.innerHTML = `<span>Listo</span>
                <svg style="width: 0.75rem; height: 0.75rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>`;
            btn.title = "Bloquear edición";
        } else {
            fs.setAttribute('disabled', 'disabled');
            fs.style.opacity = '0.8';
            fs.style.cursor = 'not-allowed';
            btn.innerHTML = `<span>Editar</span>
                <svg style="width: 0.75rem; height: 0.75rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>`;
            btn.title = "Desbloquear para editar";
        }

        btn.classList.toggle('policy-card-edit-active', isDisabled);
    }

    /**
     * Obtiene el identificador de la aplicación en contexto
     * @returns {string}
     */
    function getAppID() {
        if (window.appID) return window.appID;
        const container = document.getElementById('appDetailsContainer');
        if (container && container.dataset.appId) {
            return container.dataset.appId;
        }
        return '';
    }

    /**
     * Guarda una regla en el backend
     * @param {string} code 
     * @param {object} data 
     */
    async function saveRule(code, data) {
        const currentAppID = getAppID();
        if (!currentAppID) {
            console.error("appID no definido");
            return;
        }
        try {
            const response = await fetch(`/admin/apps/${currentAppID}/rules/${code}`, {
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
        const modeEl = document.getElementById('reg_mode');
        const roleEl = document.getElementById('reg_default_role');
        const emailEl = document.getElementById('reg_require_email_verification');

        saveRule('REGISTRATION_POLICY', {
            mode: modeEl ? modeEl.value : 'admin_only',
            default_role: roleEl ? roleEl.value : '',
            require_email_verification: emailEl ? emailEl.checked : false
        });
    }

    /**
     * Actualiza la política de contraseñas
     */
    function updatePassword() {
        const lengthEl = document.getElementById('pwd_min_length');
        const upperEl = document.getElementById('pwd_require_uppercase');
        const numEl = document.getElementById('pwd_require_numbers');
        const symEl = document.getElementById('pwd_require_symbols');

        saveRule('PWD_POLICY', {
            min_length: lengthEl ? (parseInt(lengthEl.value, 10) || 8) : 8,
            require_uppercase: upperEl ? upperEl.checked : false,
            require_numbers: numEl ? numEl.checked : false,
            require_symbols: symEl ? symEl.checked : false
        });
    }

    /**
     * Actualiza la política de sesiones
     */
    function updateSession() {
        const expEl = document.getElementById('session_expiration');
        const failEl = document.getElementById('session_max_failed');

        saveRule('SESSION_POLICY', {
            token_expiration_minutes: expEl ? (parseInt(expEl.value, 10) || 1440) : 1440,
            max_failed_logins: failEl ? (parseInt(failEl.value, 10) || 5) : 5
        });
    }

    /**
     * Actualiza la política de autorización
     */
    function updateAuthz() {
        const rolesEl = document.getElementById('authz_enable_roles');
        const enabled = rolesEl ? rolesEl.checked : false;

        const desc = document.getElementById('authz_description');
        if (desc) {
            if (enabled) {
                desc.innerText = "Los accesos están supeditados a los roles y premisos asignados.";
            } else {
                desc.innerText = "Sistema plano. Cualquier usuario autenticado tiene acceso total.";
            }
        }

        saveRule('AUTHZ_POLICY', {
            enable_roles: enabled
        });
    }

    /**
     * Actualiza la política de MFA
     */
    function updateMfa() {
        const mfaEl = document.getElementById('mfa_mode');
        saveRule('MFA_POLICY', {
            mode: mfaEl ? mfaEl.value : 'OPTIONAL'
        });
    }

    /**
     * Cambia la pestaña activa en la vista de configuración
     * @param {string} tabName 
     */
    function switchTab(tabName) {
        // Ocultar todos los contenidos de pestaña
        document.querySelectorAll('.tab-content').forEach(el => {
            el.classList.add('hidden');
        });
        // Quitar clases activas de todos los botones de pestaña
        document.querySelectorAll('.settings-tab-btn').forEach(el => {
            el.classList.remove('active-tab');
        });
        
        // Mostrar contenido de pestaña actual
        const contentEl = document.getElementById('content_' + tabName);
        if (contentEl) {
            contentEl.classList.remove('hidden');
        }
        // Añadir clase activa al botón presionado
        const btn = document.getElementById('tab_' + tabName);
        if (btn) {
            btn.classList.add('active-tab');
        }
    }

    // ==========================================
    // Delegación Centralizada de Eventos
    // ==========================================

    // Clicks: Acciones y pestañas
    document.addEventListener('click', (e) => {
        const actionBtn = e.target.closest('[data-action]');
        if (actionBtn) {
            const action = actionBtn.dataset.action;
            if (action === 'delete-app') {
                e.preventDefault();
                confirmDeleteApp();
                return;
            }
            if (action === 'revoke-secret') {
                e.preventDefault();
                openRevokeModal();
                return;
            }
            if (action === 'toggle-edit') {
                e.preventDefault();
                toggleEdit(actionBtn.dataset.section);
                return;
            }
        }

        const tabBtn = e.target.closest('[data-tab]');
        if (tabBtn) {
            e.preventDefault();
            switchTab(tabBtn.dataset.tab);
            return;
        }
    });

    // Changes: Políticas de seguridad
    document.addEventListener('change', (e) => {
        const policyEl = e.target.closest('[data-policy]');
        if (!policyEl) return;

        switch (policyEl.dataset.policy) {
            case 'registration':
                updateRegistration();
                break;
            case 'password':
                updatePassword();
                break;
            case 'session':
                updateSession();
                break;
            case 'authz':
                updateAuthz();
                break;
            case 'mfa':
                updateMfa();
                break;
        }
    });

    // ==========================================
    // Inicialización de formularios de App
    // ==========================================
    document.addEventListener("DOMContentLoaded", () => {
        const form = document.getElementById("appForm");
        const submitBtn = document.getElementById("submitBtn");

        if (form) {
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
                            title: "¿Desactivar aplicación?",
                            text: "La aplicación quedará inactiva y sus usuarios no podrán autenticarse hasta reactivarla. No se eliminará ningún dato.",
                            confirmText: "Sí, desactivar",
                            type: "warning"
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
        }

        const checkbox = document.getElementById("is_active");
        if (checkbox) {
            if (checkbox.dataset.locked === "true") {
                checkbox.addEventListener("click", (e) => {
                    e.preventDefault();
                    peakAlert("Denegado", "Esta aplicación no puede ser desactivada.", "error");
                });
            }

            const label = document.querySelector('label[for="is_active"]');
            if (label) {
                checkbox.addEventListener('change', () => {
                    label.innerText = checkbox.checked
                        ? 'Estado de la Aplicación (Activa)'
                        : 'Estado de la Aplicación (Inactiva)';
                });
            }
        }
    });
})();
