const mfaToken = window.MFA_TOKEN;

        document.addEventListener('DOMContentLoaded', async () => {
            // Load QR code
            try {
                const res = await fetch('/admin/mfa/setup', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + mfaToken }
                });
                if (res.ok) {
                    const data = await res.json();
                    if (typeof data.qr_code === 'string' && data.qr_code.startsWith('data:image/')) {
                        const img = document.createElement('img');
                        img.src = data.qr_code;
                        img.alt = 'QR Code';
                        img.style.width = '100%';
                        img.style.height = '100%';
                        img.style.objectFit = 'contain';
                        
                        const box = document.getElementById('qr-code-box');
                        box.innerHTML = '';
                        box.appendChild(img);
                    } else {
                        document.getElementById('qr-code-box').innerHTML = `<p style="color:var(--rose-600)">QR inválido</p>`;
                    }
                } else {
                    document.getElementById('qr-code-box').innerHTML = `<p style="color:var(--rose-600)">Error al cargar QR</p>`;
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
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + mfaToken 
                    },
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
