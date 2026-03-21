// Cerrar el modal de roles
function closeRoleModal() {
    document.getElementById('roleModal').classList.add('hidden');
    document.getElementById('roleForm').reset();
}

// Crear un nuevo rol
async function createRole(event) {
    event.preventDefault();
    const btn = document.getElementById('submitRoleBtn');
    const roleNameInput = document.getElementById('roleName');
    const roleName = roleNameInput.value.toUpperCase();

    btn.disabled = true;
    btn.innerText = 'Creando...';

    try {
        const response = await fetch('/admin/roles', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: roleName })
        });

        if (response.ok) {
            const select = document.querySelector('select[name="role"]');
            const option = new Option(roleName, roleName);
            select.add(option);
            select.value = roleName;
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

// Eliminar un rol
async function deleteRole(roleName) {
    const confirmed = await peakConfirm({
        title: `¿Eliminar rol "${roleName}"?`,
        text: 'Se verificará que ningún usuario tenga este rol asignado. Si alguien lo tiene, no podrá eliminarse.',
        confirmText: 'Sí, eliminar',
        type: 'danger'
    });

    if (!confirmed) return;

    try {
        const response = await fetch('/admin/roles', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: roleName })
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Rol eliminado con éxito');
            setTimeout(() => window.location.reload(), 800);
        } else {
            peakAlert('No se puede eliminar', data.error, 'warning');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión con el servidor', 'error');
    }
}

/**
 * users.js - Gestión de usuarios y roles dentro de una aplicación.
 * Permite asignar, revocar y configurar permisos de forma asíncrona.
 */

// --- Diálogos de Confirmación ---

/**
 * Confirmación para revocar el acceso de un usuario a la aplicación.
 */
async function revokeAccess(appID, userID) {
    const result = await Swal.fire({
        title: '¿Revocar acceso?',
        text: "El usuario perderá todos sus roles en esta aplicación.",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ef4444',
        cancelButtonColor: '#64748b',
        confirmButtonText: 'Sí, revocar',
        cancelButtonText: 'Cancelar',
        background: document.documentElement.classList.contains('dark') ? '#1e293b' : '#ffffff',
        color: document.documentElement.classList.contains('dark') ? '#f1f5f9' : '#1e293b'
    });

    if (result.isConfirmed) {
        try {
            const response = await fetch(`/admin/apps/${appID}/users/${userID}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                showToast('Acceso revocado');
                setTimeout(() => window.location.reload(), 800);
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
            await peakAlert('Éxito', 'Usuario y Rol vinculados correctamente a esta aplicación.', 'success');
            window.location.reload();
        } else {
            let msg = 'Error al vincular usuario';
            try {
                const data = await response.json();
                msg = data.error || msg;
            } catch(e) {
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
            setTimeout(() => window.location.reload(), 800);
        } else {
            peakAlert('Error', 'No se pudo habilitar al usuario', 'error');
        }
    } catch (err) {
        peakAlert('Error', 'Error de conexión', 'error');
    }
}
