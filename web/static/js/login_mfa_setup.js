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
                        showRecoveryCodesAndRedirect(data.recovery_codes);
                    } else {
                        window.location.href = "/admin";
                    }
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Código incorrecto',
                        text: 'Verifica el código e intenta de nuevo'
                    });
                }
            } catch (err) {
                console.error(err);
            }
        }

        function showRecoveryCodesAndRedirect(codes) {
            let html = `<div style="text-align:left; background:var(--bg-surface); padding:1rem; border-radius:0.5rem; border:1px solid var(--border-color); font-family:monospace; margin-bottom:1rem;">
                <ul style="list-style:none; padding:0; margin:0; display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">`;
            codes.forEach(c => html += `<li>${c}</li>`);
            html += `</ul></div>
                <p style="color:var(--rose-600); font-size:0.875rem; font-weight:700;">Guarda estos códigos en un lugar seguro. Solo se mostrarán esta vez.</p>`;

            Swal.fire({
                title: 'Códigos de Recuperación',
                html: html,
                icon: 'success',
                confirmButtonText: 'Los he guardado, continuar',
                allowOutsideClick: false,
                customClass: {
                    confirmButton: 'peak-btn peak-btn-primary'
                }
            }).then(() => {
                window.location.href = "/admin";
            });
        }
