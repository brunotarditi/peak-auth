document.addEventListener('DOMContentLoaded', async () => {
    const verifyButton = document.querySelector('[data-action="verify-totp"]');
    if (verifyButton) {
        verifyButton.addEventListener('click', verifyTotp);
    }

    // Load QR code - MFA token is now in HttpOnly cookie, no need to pass it
    try {
        const res = await fetch('/admin/mfa/setup', {
            method: 'POST',
            credentials: 'same-origin' // Include cookies
        });
        if (res.ok) {
                    const data = await res.json();
                    if (typeof data.qr_code === 'string' && data.qr_code.startsWith('data:image/')) {
                        const img = document.createElement('img');
                        img.src = data.qr_code;
                        img.alt = 'QR Code';
                        img.className = 'auth-qr-image';
                        
                        const box = document.getElementById('qr-code-box');
                        box.innerHTML = '';
                        box.appendChild(img);
                    } else {
                        document.getElementById('qr-code-box').innerHTML = '<p class="auth-inline-error">QR inválido</p>';
                    }
                } else {
                    document.getElementById('qr-code-box').innerHTML = '<p class="auth-inline-error">Error al cargar QR</p>';
                }
            } catch (err) {
                console.error(err);
            }
        });

        async function verifyTotp() {
            const code = document.getElementById('totp-code').value;
            if (code.length < 6) return;
            
            try {
                const res = await fetch('/admin/mfa/verify', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    credentials: 'same-origin', // Include cookies
                    body: JSON.stringify({ code: code, is_setup: true })
                });

                if (res.ok) {
                    const data = await res.json();
                    if (data.recovery_codes) {
                        const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };
                        await showRecoveryCodes(data.recovery_codes, null, themeConfig);
                        window.location.href = "/admin";
                    } else {
                        window.location.href = "/admin";
                    }
                } else {
                    peakAlert('Código incorrecto', 'Verifica el código e intenta de nuevo');
                }
            } catch (err) {
                console.error(err);
            }
        }
