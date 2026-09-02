/**
 * Sanitiza una cadena para prevenir inyecciones HTML (XSS).
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
    if (!str && str !== 0) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

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
        <div class="toast-message"></div>
        <button onclick="this.parentElement.remove()" class="toast-close">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
    `;
    toast.querySelector('.toast-message').textContent = message;

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
    const palette = window.PeakPalette || { error: '#b91c1c', warning: '#e5e843', secondary: '#3075ad', cancel: '#64748b' };
    
    const colorMap = {
        danger: { confirm: palette.error, iconColor: palette.error },
        warning: { confirm: palette.warning, iconColor: palette.warning },
        info: { confirm: palette.secondary, iconColor: palette.secondary }
    };
    const colors = colorMap[type] || colorMap.danger;

    const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };

    const result = await Swal.fire({
        title: title,
        text: text,
        icon: type === 'danger' ? 'warning' : type,
        showCancelButton: true,
        confirmButtonText: confirmText,
        cancelButtonText: 'Cancelar',
        confirmButtonColor: colors.confirm,
        cancelButtonColor: palette.cancel,
        iconColor: colors.iconColor,
        background: themeConfig.background,
        color: themeConfig.color,
        reverseButtons: true,
        buttonsStyling: false,
        customClass: {
            popup: 'peak-card',
            confirmButton: 'peak-btn peak-btn-primary',
            cancelButton: 'peak-btn peak-btn-secondary',
            actions: 'swal2-actions-custom'
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
    const palette = window.PeakPalette || { error: '#b91c1c', warning: '#e5e843', secondary: '#3075ad', success: '#10b981' };
    const colorMap = {
        error: palette.error,
        success: palette.success,
        info: palette.secondary,
        warning: palette.warning
    };
    const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };

    Swal.fire({
        title: title,
        text: text,
        icon: icon,
        confirmButtonText: 'Entendido',
        confirmButtonColor: colorMap[icon] || palette.secondary,
        background: themeConfig.background,
        color: themeConfig.color,
        buttonsStyling: false,
        customClass: {
            popup: 'peak-card',
            confirmButton: 'peak-btn peak-btn-primary'
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

/**
 * Abre el modal de configuración de MFA (TOTP)
 */
// --- Helpers para WebAuthn (Conversiones Base64URL a Uint8Array) ---
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) str += String.fromCharCode(charCode);
    const base64String = btoa(str);
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/\-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
    return outputArray.buffer;
}

async function openMfaSettings() {
    const palette = window.PeakPalette || { error: '#b91c1c', warning: '#e5e843', secondary: '#3075ad', success: '#10b981' };
    const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };

    try {
        const statusRes = await fetch('/api/v1/mfa/status');
        if (!statusRes.ok) throw new Error('No se pudo verificar el estado de MFA');
        const status = await statusRes.json();

        if (status.enabled) {
            let activeMethodsHtml = '';
            if (status.totp_configured) activeMethodsHtml += `<div style="padding: 0.75rem; background-color: rgba(16, 185, 129, 0.1); color: var(--emerald-600); border-radius: var(--radius-xl); font-size: 0.75rem; font-weight: 700; margin-bottom: 0.5rem;">Autenticador TOTP Activo</div>`;
            if (status.webauthn_configured) activeMethodsHtml += `<div style="padding: 0.75rem; background-color: rgba(8, 61, 105, 0.1); color: var(--brand-600); border-radius: var(--radius-xl); font-size: 0.75rem; font-weight: 700; margin-bottom: 0.5rem;">Llave de Seguridad (Passkey) Activa</div>`;
            
            const confirmDisable = await Swal.fire({
                title: 'Seguridad 2FA Activa',
                html: `
                    <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem;">Su cuenta está protegida con verificación de doble factor.</p>
                    ${activeMethodsHtml}
                `,
                icon: 'success',
                showCancelButton: true,
                confirmButtonText: 'Desactivar 2FA',
                cancelButtonText: 'Cerrar',
                background: themeConfig.background,
                color: themeConfig.color,
                buttonsStyling: false,
                customClass: {
                    popup: 'peak-card',
                    confirmButton: 'peak-btn peak-btn-danger',
                    cancelButton: 'peak-btn peak-btn-secondary',
                    actions: 'swal2-actions-custom'
                }
            });

            if (confirmDisable.isConfirmed) {
                const finalConfirm = await peakConfirm({
                    title: '¿Confirmar desactivación?',
                    text: 'Esto reducirá la seguridad de su cuenta.',
                    confirmText: 'Sí, Desactivar',
                    type: 'danger'
                });

                if (finalConfirm) {
                    const disableRes = await fetch('/api/v1/mfa/totp/disable', { method: 'POST' });
                    if (disableRes.ok) showToast('MFA desactivado', 'success');
                }
            }
        } else {
            // Seleccionar método de MFA
            const startSetup = await Swal.fire({
                title: 'Activar Seguridad 2FA',
                html: `
                    <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1.5rem;">Elija el método que desea usar para su segundo factor:</p>
                    <div style="display: flex; flex-direction: column; gap: 0.75rem; text-align: left;">
                        <label style="display: flex; align-items: center; gap: 0.75rem; padding: 1rem; border: 1px solid var(--border-color); border-radius: var(--radius-2xl); cursor: pointer; transition: background-color 0.2s;" onmouseover="this.style.backgroundColor='var(--bg-surface-secondary)'" onmouseout="this.style.backgroundColor='transparent'">
                            <input type="radio" name="mfa_type" value="totp" style="width: 1rem; height: 1rem; accent-color: var(--brand-600);" checked>
                            <div>
                                <span style="display: block; font-weight: 700; font-size: 0.875rem;">App Authenticator</span>
                                <span style="display: block; font-size: 0.75rem; color: var(--text-muted);">Google Auth, Authy, etc.</span>
                            </div>
                        </label>
                        <label style="display: flex; align-items: center; gap: 0.75rem; padding: 1rem; border: 1px solid var(--border-color); border-radius: var(--radius-2xl); cursor: pointer; transition: background-color 0.2s;" onmouseover="this.style.backgroundColor='var(--bg-surface-secondary)'" onmouseout="this.style.backgroundColor='transparent'">
                            <input type="radio" name="mfa_type" value="webauthn" style="width: 1rem; height: 1rem; accent-color: var(--brand-600);">
                            <div>
                                <span style="display: block; font-weight: 700; font-size: 0.875rem;">Llave de Seguridad / Passkey</span>
                                <span style="display: block; font-size: 0.75rem; color: var(--text-muted);">TouchID, FaceID o YubiKey</span>
                            </div>
                        </label>
                    </div>
                `,
                showCancelButton: true,
                confirmButtonText: 'Continuar',
                cancelButtonText: 'Cancelar',
                background: themeConfig.background,
                color: themeConfig.color,
                buttonsStyling: false,
                customClass: {
                    popup: 'peak-card',
                    confirmButton: 'peak-btn peak-btn-primary',
                    cancelButton: 'peak-btn peak-btn-secondary',
                    actions: 'swal2-actions-custom'
                },
                preConfirm: () => {
                    return document.querySelector('input[name="mfa_type"]:checked').value;
                }
            });

            if (startSetup.isConfirmed) {
                if (startSetup.value === 'totp') {
                    await setupTotp(palette, themeConfig);
                } else {
                    await setupWebAuthn(palette, themeConfig);
                }
            }
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function setupTotp(palette, themeConfig) {
    const setupRes = await fetch('/api/v1/mfa/totp/setup', { method: 'POST' });
    if (!setupRes.ok) throw new Error('Error al iniciar configuración TOTP');
    const setupData = await setupRes.json();
    const qrCode = (typeof setupData.qr_code === 'string' && setupData.qr_code.startsWith('data:image/')) 
        ? setupData.qr_code 
        : '';

    const verifyCode = await Swal.fire({
        title: 'Escanear Código QR',
        html: `
            <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1rem;">Escanee el código QR con su aplicación.</p>
            ${qrCode ? `<img src="${qrCode}" alt="QR Code" style="margin: 1rem auto; width: 12rem; height: 12rem; border: 1px solid var(--border-color); border-radius: 1.5rem; padding: 0.75rem; background-color: white;" />` : ''}
            <input id="totp-verification-code" type="text" placeholder="000000" style="width: 100%; padding: 0.75rem 1rem; background-color: var(--bg-surface-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-xl); font-family: monospace; text-align: center; font-size: 1.125rem; letter-spacing: 0.1em; font-weight: 700; outline: none;" />
        `,
        showCancelButton: true,
        confirmButtonText: 'Validar y Activar',
        cancelButtonText: 'Cancelar',
        background: themeConfig.background,
        color: themeConfig.color,
        buttonsStyling: false,
        customClass: {
            popup: 'peak-card',
            confirmButton: 'peak-btn peak-btn-primary',
            cancelButton: 'peak-btn peak-btn-secondary',
            actions: 'swal2-actions-custom'
        },
        preConfirm: () => document.getElementById('totp-verification-code').value.trim()
    });

    if (verifyCode.isConfirmed) {
        const activateRes = await fetch('/api/v1/mfa/totp/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: verifyCode.value })
        });
        if (!activateRes.ok) throw new Error('Código inválido');
        const activateData = await activateRes.json();
        await showRecoveryCodes(activateData.recovery_codes, palette, themeConfig);
    }
}

async function setupWebAuthn(palette, themeConfig) {
    if (!window.PublicKeyCredential) {
        throw new Error('Su navegador no soporta Passkeys (WebAuthn).');
    }

    const beginRes = await fetch('/api/v1/mfa/webauthn/setup', { method: 'POST' });
    if (!beginRes.ok) throw new Error('Error al iniciar configuración WebAuthn');
    const options = await beginRes.json();

    // Convertir de Base64URL a Buffer para la API del navegador
    options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
    options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials.forEach(cred => {
            cred.id = base64urlToBuffer(cred.id);
        });
    }

    try {
        const credential = await navigator.credentials.create({ publicKey: options.publicKey });
        
        // Armar el payload para el backend (volver a Base64URL)
        const credentialPayload = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            }
        };

        const finishRes = await fetch('/api/v1/mfa/webauthn/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialPayload)
        });

        if (!finishRes.ok) throw new Error('Error al validar la llave');
        
        const finishData = await finishRes.json();
        showToast('Llave configurada con éxito', 'success');
    } catch (e) {
        throw new Error('Operación de llave de seguridad cancelada o fallida');
    }
}

async function showRecoveryCodes(codes, palette, themeConfig) {
    const safeCodes = Array.isArray(codes) ? codes.map(c => escapeHtml(String(c))) : [];
    const rawCodes = Array.isArray(codes) ? codes.join('\n') : '';
    const recoveryHtml = safeCodes.map(c => `<div style="background-color: var(--bg-surface-secondary); padding: 0.5rem; border-radius: var(--radius); font-family: monospace; font-size: 0.875rem; border: 1px solid var(--border-light);">${c}</div>`).join('');
    
    await Swal.fire({
        title: '¡MFA Activado!',
        html: `
            <p style="margin-bottom: 1rem; font-size: 0.875rem; color: var(--text-muted);">Guarde estos códigos de recuperación en un lugar seguro:</p>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; margin-bottom: 1rem;">${recoveryHtml}</div>
            <button id="download-codes" class="peak-btn peak-btn-primary peak-btn-block">
                📥 Descargar Códigos (.txt)
            </button>
        `,
        icon: 'success',
        confirmButtonText: 'Entendido',
        background: themeConfig.background,
        color: themeConfig.color,
        buttonsStyling: false,
        customClass: {
            popup: 'peak-card',
            confirmButton: 'peak-btn peak-btn-secondary',
            actions: 'swal2-actions-custom'
        },
        didOpen: () => {
            document.getElementById('download-codes').addEventListener('click', () => {
                const blob = new Blob([rawCodes], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'peak_auth_recovery_codes.txt';
                a.click();
                window.URL.revokeObjectURL(url);
            });
        }
    });
}
