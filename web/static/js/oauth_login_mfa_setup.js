
        const clientID = document.body.dataset.clientId;
        let generatedCodes = [];

        document.addEventListener('DOMContentLoaded', async () => {
            const box = document.getElementById('qr-code-box');
            try {
                const res = await fetch('/api/v1/login/mfa/totp/setup', { 
                    method: 'POST',
                    headers: { 'X-App-ID': clientID }
                });
                if (!res.ok) throw new Error('No se pudo cargar el QR');
                const data = await res.json();
                
                const img = document.createElement('img');
                img.src = data.qr_code;
                img.alt = 'QR Code';
                img.className = 'oauth-qr-image';
                box.replaceChildren(img);
            } catch (err) {
                console.error(err);
                const p = document.createElement('p');
                p.className = 'oauth-qr-error';
                p.textContent = 'Error cargando el código QR';
                box.replaceChildren(p);
            }
        });

        async function verifyTotp() {
            const code = document.getElementById('totp-code').value;
            if (!code || code.length !== 6) {
                peakAlert('Error', 'Ingresa el código de 6 dígitos', 'error');
                return;
            }

            try {
                const res = await fetch('/oauth/login/mfa/setup/verify', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code: code })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Código incorrecto');

                generatedCodes = data.recovery_codes || [];
                showRecoveryCodes(generatedCodes);
            } catch (err) {
                peakAlert('Error', err.message, 'error');
            }
        }

        async function registerWebAuthn() {
            try {
                const res = await fetch('/api/v1/login/mfa/webauthn/register/begin', {
                    method: 'POST',
                    headers: { 'X-App-ID': clientID }
                });
                if (!res.ok) throw new Error('Error al iniciar WebAuthn');
                
                const options = await res.json();
                options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
                options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);

                const credential = await navigator.credentials.create({ publicKey: options.publicKey });
                
                const credentialData = {
                    id: credential.id,
                    rawId: bufferToBase64url(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferToBase64url(credential.response.attestationObject),
                        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
                    }
                };

                const finishRes = await fetch('/oauth/login/mfa/setup/webauthn/finish', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ credential: credentialData })
                });
                
                const finishData = await finishRes.json();
                if (!finishRes.ok) throw new Error(finishData.error || 'Fallo de WebAuthn');
                
                generatedCodes = finishData.recovery_codes || [];
                if (generatedCodes.length > 0) {
                    showRecoveryCodes(generatedCodes);
                } else {
                    document.getElementById('redirect-form').submit();
                }
            } catch (err) {
                console.error(err);
                peakAlert('Error', err.message, 'error');
            }
        }

        function showRecoveryCodes(codes) {
            const list = document.getElementById('recovery-codes-list');
            list.replaceChildren(...codes.map(c => {
                const d = document.createElement('div');
                d.textContent = c;
                return d;
            }));
            document.getElementById('recovery-modal').classList.add('is-visible');
        }

        function downloadRecoveryCodes() {
            const content = `Peak Auth - Códigos de Recuperación\n\nGuardá este archivo en un lugar seguro.\n\n${generatedCodes.join('\n')}`;
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'peak_auth_recovery_codes.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function continueOAuth() {
            document.getElementById('redirect-form').submit();
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let str = '';
            for (let charCode of bytes) str += String.fromCharCode(charCode);
            const base64String = btoa(str);
            return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        function base64urlToBuffer(base64url) {
            const padding = '='.repeat((4 - base64url.length % 4) % 4);
            const base64 = (base64url + padding).replace(/\-/g, '+').replace(/_/g, '/');
            const rawData = atob(base64);
            const buffer = new Uint8Array(rawData.length);
            for (let i = 0; i < rawData.length; ++i) buffer[i] = rawData.charCodeAt(i);
            return buffer.buffer;
        }

        document.addEventListener('click', (event) => {
            const action = event.target.closest('[data-action]')?.dataset.action;
            if (action === 'verify-totp') verifyTotp();
            if (action === 'register-webauthn') registerWebAuthn();
            if (action === 'download-recovery-codes') downloadRecoveryCodes();
            if (action === 'continue-oauth') continueOAuth();
        });
    