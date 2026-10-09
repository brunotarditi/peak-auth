
document.addEventListener('DOMContentLoaded', () => {
    const appId = document.getElementById('appAuditContainer')?.dataset.appId;
    if (!appId) {
        return;
    }

    const FIELD_LABELS = {
        'id': 'ID de Registro',
        'application_id': 'Aplicación',
        'user_id': 'Usuario',
        'role_id': 'Rol Asignado',
        'code': 'Código de Regla',
        'rule_type': 'Tipo de Regla',
        'value': 'Valor de la Regla',
        'rule_value': 'Valor de la Regla',
        'name': 'Nombre',
        'description': 'Descripción',
        'app_id': 'Client ID',
        'client_id': 'Client ID',
        'client_secret': 'Client Secret',
        'redirect_url': 'URL de Redirección',
        'redirect_uri': 'URI de Redirección',
        'is_active': 'Estado',
        'is_default': 'Por Defecto',
        'created_at': 'Fecha de Creación',
        'updated_at': 'Última Actualización',
        'deleted_at': 'Fecha de Eliminación',
        'email': 'Correo Electrónico',
        'is_verified': 'Email Verificado',
        'mfa_enabled': 'MFA Habilitado'
    };

    function formatLabel(k) {
        return FIELD_LABELS[k] || k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    function formatVal(k, v, entities) {
        if (v === undefined || v === null) return '<span class="app-inline-1">—</span>';
        
        // Resolver nombres de entidades (Usuario, Rol, App)
        if (entities) {
            if (k === 'user_id' && entities[`user_${v}`]) {
                return `<strong>${escapeHtml(entities[`user_${v}`])}</strong> <span class="app-inline-1">(#${escapeHtml(v)})</span>`;
            }
            if (k === 'role_id' && entities[`role_${v}`]) {
                return `<span class="peak-badge peak-badge-brand app-inline-1">${escapeHtml(entities[`role_${v}`])}</span> <span class="app-inline-1">(#${escapeHtml(v)})</span>`;
            }
            if (k === 'application_id' && entities[`app_${v}`]) {
                return `<strong>${escapeHtml(entities[`app_${v}`])}</strong> <span class="app-inline-1">(#${escapeHtml(v)})</span>`;
            }
        }

        // Booleanos con badge semántico
        if (typeof v === 'boolean') {
            if (k === 'is_active') {
                return v 
                    ? '<span class="app-inline-1">Activo</span>' 
                    : '<span class="app-inline-1">Inactivo</span>';
            }
            return v ? 'Sí' : 'No';
        }

        // Fechas legibles (ISO 8601 o claves que terminan en _at)
        if (typeof v === 'string' && (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(v) || k.endsWith('_at'))) {
            try {
                const d = new Date(v);
                if (!isNaN(d.getTime())) {
                    const pad = n => String(n).padStart(2, '0');
                    const day = pad(d.getDate());
                    const month = pad(d.getMonth() + 1);
                    const year = d.getFullYear();
                    const hours = pad(d.getHours());
                    const mins = pad(d.getMinutes());
                    const secs = pad(d.getSeconds());
                    return `<span class="app-inline-1">${day}/${month}/${year} ${hours}:${mins}:${secs}</span>`;
                }
            } catch (_) {}
        }

        // Objetos JSON anidados
        if (typeof v === 'object') {
            return `<pre class="app-inline-1">${escapeHtml(JSON.stringify(v, null, 2))}</pre>`;
        }

        return `<span class="app-inline-1">${escapeHtml(String(v))}</span>`;
    }

    document.querySelectorAll('.btn-inspect-diff').forEach(btn => {
        btn.addEventListener('click', async () => {
            const logId = btn.getAttribute('data-id');
            try {
                btn.disabled = true;
                const res = await fetch(`/admin/apps/${encodeURIComponent(appId)}/audit/${encodeURIComponent(logId)}`);
                if (!res.ok) {
                    showToast('No se pudo cargar el detalle del evento', 'error');
                    return;
                }
                const data = await res.json();
                showDiffModal(data);
            } catch (err) {
                console.error(err);
                showToast('Error al consultar el detalle de auditoría', 'error');
            } finally {
                btn.disabled = false;
            }
        });
    });

    function showDiffModal(log) {
        const oldData = log.old_data || {};
        const newData = log.new_data || {};
        const entities = log.entities || {};

        // Filtrar atributos irrelevantes (ej. deleted_at nulo) y ordenar campos clave primero
        const allKeys = Array.from(new Set([...Object.keys(oldData), ...Object.keys(newData)]));
        const filteredKeys = allKeys.filter(k => {
            if (k === 'deleted_at' && (newData[k] === null || newData[k] === undefined) && (oldData[k] === null || oldData[k] === undefined)) {
                return false;
            }
            return true;
        }).sort((a, b) => {
            const priority = { 'user_id': 1, 'role_id': 2, 'application_id': 3, 'code': 4, 'rule_type': 5, 'value': 6, 'rule_value': 7, 'name': 8, 'app_id': 9, 'is_active': 10, 'created_at': 20, 'updated_at': 21, 'id': 30 };
            const pA = priority[a] || 50;
            const pB = priority[b] || 50;
            if (pA !== pB) return pA - pB;
            return a.localeCompare(b);
        });

        let diffHtml = '';

        if (log.action === 'INSERT') {
            diffHtml = `
                <div class="app-inline-1">
                    <div class="app-inline-1">Valores Iniciales Creados:</div>
                    <table class="app-inline-1">
                        ${filteredKeys.map(k => `
                            <tr class="app-inline-1">
                                <td class="app-inline-1">${escapeHtml(formatLabel(k))}</td>
                                <td class="app-inline-1">${formatVal(k, newData[k], entities)}</td>
                            </tr>
                        `).join('')}
                    </table>
                </div>
            `;
        } else if (log.action === 'DELETE') {
            diffHtml = `
                <div class="app-inline-1">
                    <div class="app-inline-1">Valores Previos al Borrado:</div>
                    <table class="app-inline-1">
                        ${filteredKeys.map(k => `
                            <tr class="app-inline-1">
                                <td class="app-inline-1">${escapeHtml(formatLabel(k))}</td>
                                <td class="app-inline-1">${formatVal(k, oldData[k], entities)}</td>
                            </tr>
                        `).join('')}
                    </table>
                </div>
            `;
        } else {
            // UPDATE: mostrar comparativa de campos modificados
            const changedKeys = filteredKeys.filter(k => JSON.stringify(oldData[k]) !== JSON.stringify(newData[k]));
            if (changedKeys.length === 0) {
                diffHtml = '<p class="app-inline-1">No se detectaron cambios en los atributos del registro.</p>';
            } else {
                diffHtml = `
                    <div class="app-inline-1">
                        <table class="app-inline-1">
                            <thead>
                                <tr class="app-inline-1">
                                    <th class="app-inline-1">Campo</th>
                                    <th class="app-inline-1">Valor Anterior</th>
                                    <th class="app-inline-1">Valor Nuevo</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${changedKeys.map(k => `
                                    <tr class="app-inline-1">
                                        <td class="app-inline-1">${escapeHtml(formatLabel(k))}</td>
                                        <td class="app-inline-1">${formatVal(k, oldData[k], entities)}</td>
                                        <td class="app-inline-1">${formatVal(k, newData[k], entities)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        }

        let headerSubtitle = `<strong>Recurso:</strong> ${escapeHtml(log.table_label || log.table_name)} • <strong>Acción:</strong> ${escapeHtml(log.action)} • <strong>Registro:</strong> #${escapeHtml(log.record_id)}`;
        if (log.changed_by && log.changed_by !== 'postgres' && log.changed_by !== 'Sistema') {
            headerSubtitle += ` • <strong>Actor:</strong> ${escapeHtml(log.changed_by)}`;
        }

        PeakModal.fire({
            title: `Detalle del Evento #${log.id}`,
            html: `
                <div class="app-inline-1">
                    ${headerSubtitle}
                </div>
                ${diffHtml}
            `,
            confirmButtonText: 'Cerrar'
        });
    }
});
