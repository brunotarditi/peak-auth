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

                const beginHeaders = {};
                if (mfaToken) {
                    beginHeaders['Authorization'] = 'Bearer ' + mfaToken;
                }

                const beginRes = await fetch('/admin/login/mfa/webauthn/begin', {
                    method: 'GET',
                    headers: beginHeaders
                });

                if (!beginRes.ok) {
                    const err = await beginRes.json();
                    throw new Error(err.error || 'Error al iniciar WebAuthn');
                }

                const options = await beginRes.json();
                options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
                options.publicKey.allowCredentials.forEach(cred => {
                    cred.id = base64urlToBuffer(cred.id);
                });

                const credential = await navigator.credentials.get({
                    publicKey: options.publicKey
                });

                const authData = {
                    id: credential.id,
                    rawId: bufferToBase64url(credential.rawId),
                    type: credential.type,
                    response: {
                        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                        signature: bufferToBase64url(credential.response.signature),
                        userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                    }
                };

                const finishHeaders = {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                };
                if (mfaToken) {
                    finishHeaders['Authorization'] = 'Bearer ' + mfaToken;
                }

                const finishRes = await fetch('/admin/login/mfa/webauthn/finish', {
                    method: 'POST',
                    headers: finishHeaders,
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
                
                PeakModal.fire({
                    title: 'Error',
                    text: err.message,
                    icon: 'error',
                    confirmButtonText: 'Entendido'
                });
                
                btnWebAuthn.disabled = false;
                btnWebAuthn.innerHTML = '<span>Llave de Seguridad (Passkey)</span>';
            }
        });
    }
});
