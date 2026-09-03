(() => {
    'use strict';

    /**
     * users.js - Gestión de usuarios y roles dentro de una aplicación.
     * Permite asignar, revocar y configurar permisos de forma asíncrona.
     */

// Abrir el modal de roles
function openRoleModal() {
    document.getElementById('roleModal').classList.remove('hidden');
}


// Cerrar el modal de roles
function closeRoleModal() {
    document.getElementById('roleModal').classList.add('hidden');
    document.getElementById('roleForm').reset();
}

// Crear un nuevo rol propio de la aplicación
async function createRole(event, appID) {
    event.preventDefault();
    const btn = document.getElementById('submitRoleBtn');
    const roleNameInput = document.getElementById('roleName');
    const roleName = roleNameInput.value.toUpperCase().trim();

    if (!roleName) return;

    btn.disabled = true;
    btn.innerText = 'Creando...';

    try {
        const response = await fetch(`/admin/apps/${appID}/roles`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: roleName })
        });

        if (response.ok) {
            // Actualizar select del formulario
            const select = document.querySelector('select[name="role"]');
            if (select) {
                const option = new Option(roleName, roleName);
                select.add(option);
                select.value = roleName;
            }

            // Agregar al listado de roles del modal dinámicamente
            const modalList = document.getElementById('modal-roles-list');
            if (modalList) {
                const item = document.createElement('div');
                item.id = `modal-role-item-${roleName}`;
                item.className = 'group';
                item.style.cssText = 'display: flex; align-items: center; justify-content: space-between; padding: 0.75rem; background-color: var(--bg-surface-secondary); border-radius: var(--radius-xl); border: 1px solid var(--border-light); transition: all 0.2s ease;';

                const nameSpan = document.createElement('span');
                nameSpan.style.cssText = 'font-size: 0.875rem; font-weight: 700; color: var(--text-main);';
                nameSpan.textContent = roleName;

                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'icon-btn icon-btn-danger';
                delBtn.style.padding = '0.25rem';
                delBtn.title = 'Eliminar Rol';
                delBtn.setAttribute('aria-label', `Eliminar rol ${roleName}`);
                delBtn.innerHTML = '<svg style="width:1rem;height:1rem" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>';
                delBtn.onclick = () => deleteRole(roleName, appID);

                item.appendChild(nameSpan);
                item.appendChild(delBtn);
                modalList.appendChild(item);
            }

            closeRoleModal();
            showToast('Rol creado con éxito');
        } else {
            const data = await response.json();
            peakAlert('Error', data.error || 'No se pudo crear el rol', 'error');
        }
    } catch (err) {
        peakAlert('Error de conexión', 'No se pudo conectar con el servidor', 'error');
    } finally {
        btn.disabled = false;
        btn.innerText = 'Crear Rol';
    }
}

// Eliminar un rol propio de la aplicación
async function deleteRole(roleName, appID) {
    const confirmed = await peakConfirm({
        title: `¿Eliminar rol "${roleName}"?`,
        text: 'Se verificará que ningún usuario tenga este rol asignado. Si alguien lo tiene, no podrá eliminarse.',
        confirmText: 'Sí, eliminar',
        type: 'danger'
    });

    if (!confirmed) return;

    try {
        const response = await fetch(`/admin/apps/${appID}/roles/${encodeURIComponent(roleName)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Rol eliminado con éxito');

            // Remover del modal con animación
            const item = document.getElementById(`modal-role-item-${roleName}`);
            if (item) {
                item.style.opacity = '0';
                item.style.transform = 'scale(0.95)';
                setTimeout(() => item.remove(), 200);
            }

            // Remover del select de asignación
            const select = document.querySelector('select[name="role"]');
            if (select) {
                const opt = select.querySelector(`option[value="${roleName}"]`);
                if (opt) opt.remove();
            }
        } else {
            peakAlert('No se puede eliminar', data.error, 'warning');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión con el servidor', 'error');
    }
}

// Revocar el acceso de un usuario a la aplicación.
async function revokeAccess(appID, userID) {
    const confirmed = await peakConfirm({
        title: '¿Revocar acceso?',
        text: 'El usuario perderá todos sus roles en esta aplicación.',
        confirmText: 'Sí, revocar',
        type: 'danger'
    });

    if (confirmed) {
        try {
            const response = await fetch(`/admin/apps/${appID}/users/${userID}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                showToast('Acceso revocado');

                // Animar y remover la fila del DOM
                const row = document.getElementById(`user-row-${userID}`);
                if (row) {
                    row.style.opacity = '0';
                    row.style.transform = 'translateY(-6px)';
                    setTimeout(() => {
                        row.remove();

                        // Decrementar el contador
                        const totalBadge = document.getElementById('user-total-count');
                        if (totalBadge) {
                            const match = totalBadge.textContent.match(/\d+/);
                            if (match) {
                                const newCount = Math.max(0, parseInt(match[0], 10) - 1);
                                totalBadge.textContent = `Total: ${newCount}`;
                            }
                        }

                        // Verificar si la tabla quedó sin usuarios
                        const tbody = document.getElementById('users-table-body');
                        if (tbody && tbody.querySelectorAll('tr').length === 0) {
                            tbody.innerHTML = `
                                <tr id="empty-users-row">
                                    <td colspan="3" style="text-align: center; padding: 4rem 1.5rem;">
                                        <div style="width: 3.5rem; height: 3.5rem; border-radius: 9999px; background-color: var(--bg-surface-secondary); border: 1px solid var(--border-light); color: var(--text-light); display: inline-flex; align-items: center; justify-content: center; margin-bottom: 1rem;">
                                            <svg style="width: 1.75rem; height: 1.75rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                            </svg>
                                        </div>
                                        <h4 style="font-size: 1rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem;">No hay usuarios vinculados</h4>
                                        <p style="font-size: 0.875rem; color: var(--text-muted); max-width: 22rem; margin: 0 auto; line-height: 1.5;">Utiliza el formulario de la izquierda para vincular el primer usuario a esta aplicación.</p>
                                    </td>
                                </tr>
                            `;
                        }
                    }, 300);
                }
            } else {
                peakAlert('Error', 'No se pudo revocar el acceso', 'error');
            }
        } catch (err) {
            peakAlert('Error', 'Error de conexión', 'error');
        }
    }
}

// Asignar acceso a un usuario
async function assignUser(event, appID) {
    event.preventDefault();
    const form = event.target;
    const email = form.email.value;
    const role = form.role.value;
    const btn = form.querySelector('button[type="submit"]');

    btn.disabled = true;

    try {
        const body = new URLSearchParams();
        body.append('email', email);
        body.append('role', role);

        const response = await fetch(`/admin/apps/${appID}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        });

        if (response.ok) {
            showToast('Usuario vinculado con éxito');
            // Recargar suavemente para reflejar la paginación y datos de auditoría
            setTimeout(() => window.location.reload(), 500);
        } else {
            let msg = 'Error al vincular usuario';
            try {
                const data = await response.json();
                msg = data.error || msg;
            } catch (e) {
                msg = await response.text();
            }
            peakAlert('Error al vincular', msg, 'error');
        }
    } catch (e) {
        peakAlert('Servidor Inaccesible', 'Problema al conectar con el backend.', 'error');
    } finally {
        btn.disabled = false;
    }
}

// Desbloquear usuario (resetear intentos fallidos)
async function unlockUser(appID, userID) {
    try {
        const response = await fetch(`/admin/apps/${appID}/users/${userID}/unlock`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast('Usuario habilitado correctamente');

            // Remover badge de intentos y botón de desbloqueo dinámicamente
            const badge = document.getElementById(`user-failed-badge-${userID}`);
            if (badge) {
                badge.style.opacity = '0';
                badge.style.transform = 'scale(0.8)';
                badge.style.transition = 'all 0.2s ease';
                setTimeout(() => badge.remove(), 200);
            }

            const btn = document.getElementById(`btn-unlock-${userID}`);
            if (btn) {
                btn.style.opacity = '0';
                btn.style.transform = 'scale(0.8)';
                btn.style.transition = 'all 0.2s ease';
                setTimeout(() => btn.remove(), 200);
            }
        } else {
            peakAlert('Error', 'No se pudo habilitar al usuario', 'error');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión', 'error');
    }
}

// Reenviar email de verificación
async function resendVerification(appID, userID) {
    try {
        const response = await fetch(`/admin/apps/${appID}/users/${userID}/resend-verification`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast('Email de activación reenviado');
        } else {
            const data = await response.json();
            peakAlert('Error', data.error || 'No se pudo reenviar el email', 'error');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión', 'error');
    }
}

// Enviar email de reset de password manualmente
async function sendResetPassword(appID, userID) {
    try {
        const response = await fetch(`/admin/apps/${appID}/users/${userID}/send-reset`, {
            method: 'POST'
        });

        if (response.ok) {
            showToast('Email de recuperación enviado');
        } else {
            const data = await response.json();
            peakAlert('Error', data.error || 'No se pudo enviar el email', 'error');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión', 'error');
    }
}

// Event listeners para los botones del modal de roles
document.addEventListener('DOMContentLoaded', () => {
    const openRoleBtn = document.getElementById('openRoleModalBtn');
    const closeRoleBtn = document.getElementById('closeRoleModalBtn');
    const roleBackdrop = document.getElementById('roleModalBackdrop');

    if (openRoleBtn) {
        openRoleBtn.addEventListener('click', openRoleModal);
    }

    if (closeRoleBtn) {
        closeRoleBtn.addEventListener('click', closeRoleModal);
    }

    if (roleBackdrop) {
        roleBackdrop.addEventListener('click', closeRoleModal);
    }
});

    // Exportar funciones para eventos HTML inline inmediatamente
    window.openRoleModal = openRoleModal;
    window.closeRoleModal = closeRoleModal;
    window.createRole = createRole;
    window.deleteRole = deleteRole;
    window.revokeAccess = revokeAccess;
    window.assignUser = assignUser;
    window.unlockUser = unlockUser;
    window.resendVerification = resendVerification;
    window.sendResetPassword = sendResetPassword;
})();
