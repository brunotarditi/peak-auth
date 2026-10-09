
        const clientID = document.body.dataset.clientId;

        async function verifyTotp() {
            const code = document.getElementById('totp-code').value;
            if (!code || code.length !== 6) {
                peakAlert('Error', 'Ingresa el código de 6 dígitos', 'error');
                return;
            }

            try {
                const res = await fetch('/oauth/login/mfa/totp', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code: code })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Código incorrecto');

                document.getElementById('redirect-form').submit();
            } catch (err) {
                peakAlert('Error', err.message, 'error');
            }
        }

        async function loginWebAuthn() {
            try {
                const res = await fetch('/api/v1/login/mfa/webauthn/begin', {
                    headers: { 'X-App-ID': clientID }
                });
                if (!res.ok) throw new Error('Error al iniciar WebAuthn');
                
                const options = await res.json();
                
                options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
                if (options.publicKey.allowCredentials) {
                    options.publicKey.allowCredentials.forEach(cred => {
                        cred.id = base64urlToBuffer(cred.id);
                    });
                }

                const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
                
                const assertionResponse = {
                    id: assertion.id,
                    rawId: bufferToBase64url(assertion.rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                        clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                        signature: bufferToBase64url(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
                    }
                };

                const finishRes = await fetch('/oauth/login/mfa/webauthn/finish', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ assertion: assertionResponse })
                });
                
                const finishData = await finishRes.json();
                if (!finishRes.ok) throw new Error(finishData.error || 'Fallo de WebAuthn');
                
                document.getElementById('redirect-form').submit();
            } catch (err) {
                console.error(err);
                peakAlert('Error', err.message, 'error');
            }
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
            if (action === 'login-webauthn') loginWebAuthn();
        });
    