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

        const originalNodes = Array.from(btn.childNodes);
        
        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("class", "w-5 h-5");
        svg.setAttribute("fill", "none");
        svg.setAttribute("stroke", "currentColor");
        svg.setAttribute("viewBox", "0 0 24 24");
        const path = document.createElementNS(svgNS, "path");
        path.setAttribute("stroke-linecap", "round");
        path.setAttribute("stroke-linejoin", "round");
        path.setAttribute("stroke-width", "2");
        path.setAttribute("d", "M5 13l4 4L19 7");
        svg.appendChild(path);

        btn.replaceChildren(svg);
        showToast('Copiado con éxito', 'success', 2000);

        setTimeout(() => {
            btn.replaceChildren(...originalNodes);
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
    const isDanger = type === 'danger';
    const confirmBtnClass = isDanger ? 'peak-btn peak-modal-btn-danger' : 'peak-btn peak-btn-primary';

    const result = await PeakModal.fire({
        title: title,
        text: text,
        icon: isDanger ? 'danger' : type,
        showCancelButton: true,
        confirmButtonText: confirmText,
        cancelButtonText: 'Cancelar',
        reverseButtons: true,
        customClass: {
            confirmButton: confirmBtnClass,
            cancelButton: 'peak-btn peak-modal-btn-cancel',
            actions: 'peak-modal-actions'
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
    return PeakModal.fire({
        title: title,
        text: text,
        icon: icon,
        confirmButtonText: 'Entendido',
        customClass: {
            confirmButton: 'peak-btn peak-modal-btn-confirm'
        }
    });
}

/**
 * Alternar visibilidad de contraseña en el campo de login
 * @param {string} fieldId - ID del campo input tipo password
 * @param {HTMLElement} [btn] - Botón que ejecutó la acción
 */
function toggleLoginPassword(fieldId, btn) {
    const input = document.getElementById(fieldId);
    if (!input) return;

    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';

    const button = btn || (typeof event !== 'undefined' && event ? event.currentTarget : null);
    if (button) {
        const eyeOpen = button.querySelector('.icon-eye-open');
        const eyeClosed = button.querySelector('.icon-eye-closed');
        if (eyeOpen && eyeClosed) {
            if (isPassword) {
                eyeOpen.classList.add('hidden');
                eyeClosed.classList.remove('hidden');
            } else {
                eyeOpen.classList.remove('hidden');
                eyeClosed.classList.add('hidden');
            }
        }
    }
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
            let totpHtml = '';
            if (status.totp_configured) {
                totpHtml = `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background-color: var(--bg-surface-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-xl); margin-bottom: 1rem;">
                        <div style="display: flex; align-items: center; gap: 0.75rem; text-align: left;">
                            <span style="font-size: 1.25rem;">📱</span>
                            <div>
                                <div style="font-weight: 700; font-size: 0.875rem; color: var(--text-main);">App Authenticator (TOTP)</div>
                                <div style="font-size: 0.75rem; color: var(--emerald-600); font-weight: 600;">● Activo</div>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                totpHtml = `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background-color: var(--bg-surface-secondary); border: 1px dashed var(--border-color); border-radius: var(--radius-xl); margin-bottom: 1rem;">
                        <div style="display: flex; align-items: center; gap: 0.75rem; text-align: left;">
                            <span style="font-size: 1.25rem;">📱</span>
                            <div>
                                <div style="font-weight: 700; font-size: 0.875rem; color: var(--text-main);">App Authenticator (TOTP)</div>
                                <div style="font-size: 0.75rem; color: var(--text-muted);">No configurada</div>
                            </div>
                        </div>
                        <button type="button" id="btn-modal-add-totp" class="peak-btn peak-btn-secondary" style="padding: 0.375rem 0.75rem; font-size: 0.75rem;">
                            + Configurar
                        </button>
                    </div>
                `;
            }

            const keys = status.webauthn_keys || [];
            let keysListHtml = '';
            if (keys.length > 0) {
                keysListHtml = keys.map(k => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0.75rem; background-color: var(--bg-surface-secondary); border: 1px solid var(--border-light); border-radius: var(--radius-lg); margin-bottom: 0.5rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem; text-align: left;">
                            <span style="font-size: 1rem;">🔑</span>
                            <div>
                                <div style="font-weight: 600; font-size: 0.8125rem; color: var(--text-main);">${escapeHtml(k.name || 'Llave de Seguridad')}</div>
                                <div style="font-size: 0.6875rem; color: var(--text-muted);">${new Date(k.created_at).toLocaleDateString()}</div>
                            </div>
                        </div>
                        <button type="button" class="btn-modal-del-key icon-btn icon-btn-danger" data-id="${k.id}" data-name="${escapeHtml(k.name || 'Llave')}" title="Eliminar llave" style="padding: 0.25rem; width: 1.75rem; height: 1.75rem;">
                            <svg style="width: 0.875rem; height: 0.875rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                        </button>
                    </div>
                `).join('');
            } else {
                keysListHtml = `<div style="font-size: 0.75rem; color: var(--text-muted); padding: 0.5rem 0; text-align: left;">No tienes llaves físicas o Passkeys registradas.</div>`;
            }

            let addKeyBtnHtml = '';
            if (keys.length < 5) {
                addKeyBtnHtml = `
                    <button type="button" id="btn-modal-add-webauthn" class="peak-btn peak-btn-secondary" style="width: 100%; font-size: 0.75rem; padding: 0.5rem; margin-top: 0.25rem;">
                        + Agregar Llave / Passkey (${keys.length}/5)
                    </button>
                `;
            } else {
                addKeyBtnHtml = `<div style="font-size: 0.6875rem; color: var(--text-muted); margin-top: 0.5rem;">Límite alcanzado (máximo 5 llaves).</div>`;
            }

            await PeakModal.fire({
                title: 'Seguridad Multi-Factor (2FA)',
                html: `
                    <div style="text-align: left; margin-bottom: 1rem;">
                        <p style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 1rem;">Gestiona tus métodos de autenticación multi-factor activos.</p>
                        
                        <div style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem;">Aplicación Móvil</div>
                        ${totpHtml}

                        <div style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem;">Llaves de Seguridad / Passkeys</div>
                        <div style="margin-bottom: 0.5rem;">
                            ${keysListHtml}
                        </div>
                        ${addKeyBtnHtml}
                    </div>
                `,
                showCancelButton: true,
                showConfirmButton: true,
                confirmButtonText: 'Desactivar todo el 2FA',
                cancelButtonText: 'Cerrar',
                background: themeConfig.background,
                color: themeConfig.color,
                buttonsStyling: false,
                customClass: {
                    popup: 'peak-card',
                    confirmButton: 'peak-btn peak-btn-danger',
                    cancelButton: 'peak-btn peak-btn-secondary',
                    actions: 'swal2-actions-custom'
                },
                didOpen: () => {
                    const addTotpBtn = document.getElementById('btn-modal-add-totp');
                    if (addTotpBtn) {
                        addTotpBtn.addEventListener('click', async () => {
                            PeakModal.close();
                            await setupTotp(palette, themeConfig);
                            await openMfaSettings();
                        });
                    }

                    const addWebAuthnBtn = document.getElementById('btn-modal-add-webauthn');
                    if (addWebAuthnBtn) {
                        addWebAuthnBtn.addEventListener('click', async () => {
                            PeakModal.close();
                            const namePrompt = await PeakModal.fire({
                                title: 'Nueva Llave / Passkey',
                                html: `
                                    <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem;">Ingresa un nombre para identificar tu llave (ej: "YubiKey Principal", "MacBook TouchID"):</p>
                                    <input id="key-custom-name" type="text" class="peak-input" placeholder="Nombre de la llave" value="Mi Llave de Seguridad" />
                                `,
                                showCancelButton: true,
                                confirmButtonText: 'Registrar Llave',
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
                                    const val = document.getElementById('key-custom-name').value.trim();
                                    return val || 'Mi Llave de Seguridad';
                                }
                            });

                            if (namePrompt.isConfirmed) {
                                try {
                                    await setupWebAuthn(palette, themeConfig, namePrompt.value);
                                } catch (err) {
                                    showToast(err.message, 'error');
                                }
                                await openMfaSettings();
                            } else {
                                await openMfaSettings();
                            }
                        });
                    }

                    document.querySelectorAll('.btn-modal-del-key').forEach(btn => {
                        btn.addEventListener('click', async (e) => {
                            e.stopPropagation();
                            const keyId = btn.getAttribute('data-id');
                            const keyName = btn.getAttribute('data-name');
                            PeakModal.close();

                            const confirmDel = await PeakModal.fire({
                                title: '¿Eliminar llave?',
                                html: `<p style="font-size: 0.875rem; color: var(--text-muted);">¿Estás seguro de que deseas eliminar la llave <strong>${escapeHtml(keyName)}</strong>?</p>`,
                                icon: 'warning',
                                showCancelButton: true,
                                confirmButtonText: 'Sí, eliminar',
                                cancelButtonText: 'Cancelar',
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

                            if (confirmDel.isConfirmed) {
                                try {
                                    const delRes = await fetch('/api/v1/mfa/webauthn/credentials/' + keyId, {
                                        method: 'DELETE'
                                    });
                                    if (delRes.ok) {
                                        showToast('Llave eliminada correctamente', 'success');
                                    } else {
                                        const err = await delRes.json();
                                        showToast(err.error || 'Error al eliminar la llave', 'error');
                                    }
                                } catch (err) {
                                    showToast('Error al conectar con el servidor', 'error');
                                }
                            }
                            await openMfaSettings();
                        });
                    });
                }
            }).then(async (result) => {
                if (result.isConfirmed) {
                    const stepUpConfirm = await PeakModal.fire({
                        title: 'Confirmar Desactivación',
                        html: `
                            <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1rem;">Para confirmar la desactivación de 2FA, ingrese su contraseña actual o un código de verificación:</p>
                            <input id="stepup-credential" type="password" class="peak-input" placeholder="Contraseña o código 2FA" autocomplete="current-password" />
                        `,
                        showCancelButton: true,
                        confirmButtonText: 'Sí, Desactivar',
                        cancelButtonText: 'Cancelar',
                        background: themeConfig.background,
                        color: themeConfig.color,
                        buttonsStyling: false,
                        customClass: {
                            popup: 'peak-card',
                            confirmButton: 'peak-btn peak-btn-danger',
                            cancelButton: 'peak-btn peak-btn-secondary',
                            actions: 'swal2-actions-custom'
                        },
                        preConfirm: () => {
                            const val = document.getElementById('stepup-credential').value.trim();
                            if (!val) {
                                PeakModal.showValidationMessage('Debe ingresar su contraseña o código');
                                return false;
                            }
                            return val;
                        }
                    });

                    if (stepUpConfirm.isConfirmed) {
                        const cred = stepUpConfirm.value;
                        const disableRes = await fetch('/api/v1/mfa/totp/disable', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ password: cred, code: cred })
                        });
                        if (disableRes.ok) {
                            showToast('MFA desactivado correctamente', 'success');
                        } else {
                            const errData = await disableRes.json();
                            showToast(errData.error || 'Error al desactivar MFA', 'error');
                        }
                    }
                }
            });
        } else {
            // Seleccionar método de MFA
            const startSetup = await PeakModal.fire({
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

    const verifyCode = await PeakModal.fire({
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

async function setupWebAuthn(palette, themeConfig, keyName) {
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

        const verifyUrl = '/api/v1/mfa/webauthn/verify' + (keyName ? '?name=' + encodeURIComponent(keyName) : '');
        const finishRes = await fetch(verifyUrl, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Key-Name': keyName || 'Llave de Seguridad'
            },
            body: JSON.stringify(credentialPayload)
        });

        if (!finishRes.ok) throw new Error('Error al validar la llave');
        
        const finishData = await finishRes.json();
        showToast('Llave configurada con éxito', 'success');
        if (finishData.recovery_codes) {
            await showRecoveryCodes(finishData.recovery_codes, palette, themeConfig);
        }
    } catch (e) {
        if (e.name === 'NotAllowedError') {
            throw new Error('Operación cancelada por el usuario');
        }
        throw new Error(e.message || 'Operación de llave de seguridad cancelada o fallida');
    }
}

async function showRecoveryCodes(codes, palette, themeConfig) {
    const safeCodes = Array.isArray(codes) ? codes.map(c => escapeHtml(String(c))) : [];
    const rawCodes = Array.isArray(codes) ? codes.join('\n') : '';
    const recoveryHtml = safeCodes.map(c => `<div style="background-color: var(--bg-surface-secondary); padding: 0.5rem; border-radius: var(--radius); font-family: monospace; font-size: 0.875rem; border: 1px solid var(--border-light);">${c}</div>`).join('');
    
    await PeakModal.fire({
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
