function closeRoleModal() {
    document.getElementById('roleModal').classList.add('hidden');
    document.getElementById('roleForm').reset();
}

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
            showToast(data.error || 'No se pudo crear el rol', 'error');
        }
    } catch (err) {
        showToast('Error de conexión', 'error');
    } finally {
        btn.disabled = false;
        btn.innerText = 'Crear Rol';
    }
}

async function revokeAccess(appID, userID) {
    if (!confirm('¿Seguro que quieres revocar el acceso a este usuario?')) return;
    showToast('Funcionalidad de revocación pendiente de backend', 'error');
}
