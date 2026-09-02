document.addEventListener('DOMContentLoaded', () => {
    const btnWebAuthn = document.getElementById('btn-webauthn');
    if (btnWebAuthn) {
        btnWebAuthn.addEventListener('click', async () => {
            const mfaToken = document.querySelector('input[name="mfa_token"]').value;
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;
            
            try {
                if (!window.PublicKeyCredential) {
                    throw new Error('Su navegador no soporta Passkeys (WebAuthn).');
                }

                btnWebAuthn.disabled = true;
                btnWebAuthn.innerHTML = '<span>Verificando...</span>';

                const beginRes = await fetch('/admin/login/mfa/webauthn/begin?mfa_token=' + encodeURIComponent(mfaToken), {
                    method: 'GET'
                });

                if (!beginRes.ok) {
                    const err = await beginRes.json();
                    throw new Error(err.error || 'Error al iniciar WebAuthn');
                }

                const options = await beginRes.json();
                options.publicKey.challenge = bufferDecode(options.publicKey.challenge);
                options.publicKey.allowCredentials.forEach(cred => {
                    cred.id = bufferDecode(cred.id);
                });

                const credential = await navigator.credentials.get({
                    publicKey: options.publicKey
                });

                const authData = {
                    id: credential.id,
                    rawId: bufferEncode(credential.rawId),
                    type: credential.type,
                    response: {
                        authenticatorData: bufferEncode(credential.response.authenticatorData),
                        clientDataJSON: bufferEncode(credential.response.clientDataJSON),
                        signature: bufferEncode(credential.response.signature),
                        userHandle: credential.response.userHandle ? bufferEncode(credential.response.userHandle) : null
                    }
                };

                const finishRes = await fetch('/admin/login/mfa/webauthn/finish?mfa_token=' + encodeURIComponent(mfaToken), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(authData)
                });

                if (finishRes.ok) {
                    window.location.href = '/admin';
                } else {
                    const err = await finishRes.json();
                    throw new Error(err.error || 'Error al verificar credencial');
                }
            } catch (err) {
                console.error(err);
                
                const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };
                Swal.fire({
                    title: 'Error',
                    text: err.message,
                    icon: 'error',
                    confirmButtonColor: window.PeakPalette ? window.PeakPalette.error : '#b91c1c',
                    background: themeConfig.background,
                    color: themeConfig.color
                });
                
                btnWebAuthn.disabled = false;
                btnWebAuthn.innerHTML = '<span>Llave de Seguridad (Passkey)</span>';
            }
        });
    }
});
