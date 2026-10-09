(() => {
    'use strict';

document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('formVerifySetupMfa');
        const codeInput = document.getElementById('totpCodeInput');
        const feedback = document.getElementById('setupMfaFeedback');
        const submitBtn = document.getElementById('btnSubmitMfa');
        const setupStep = document.getElementById('mfaSetupStep');
        const recoveryStep = document.getElementById('mfaRecoveryStep');
        const recoveryCodesContainer = document.getElementById('recoveryCodesContainer');
        const btnCopyCodes = document.getElementById('btnCopyCodes');
        const btnDownloadCodes = document.getElementById('btnDownloadCodes');

        let generatedCodes = [];

        function showFeedback(msg, isSuccess) {
            feedback.textContent = msg;
            feedback.style.display = 'block';
            if (isSuccess) {
                feedback.style.backgroundColor = 'rgba(16, 185, 129, 0.12)';
                feedback.style.color = 'var(--emerald-600)';
                feedback.style.border = '1px solid rgba(16, 185, 129, 0.25)';
            } else {
                feedback.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
                feedback.style.color = 'var(--danger-600)';
                feedback.style.border = '1px solid rgba(239, 68, 68, 0.25)';
            }
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = codeInput.value.trim();
            if (code.length !== 6) {
                showFeedback('El código debe tener exactamente 6 dígitos', false);
                return;
            }

            submitBtn.disabled = true;

            try {
                const res = await fetch('/setup/mfa/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': '{{ .CSRFToken }}'
                    },
                    body: JSON.stringify({ code })
                });

                const data = await res.json();
                if (res.ok && data.success) {
                    generatedCodes = data.recovery_codes || [];
                    recoveryCodesContainer.innerHTML = '';
                    generatedCodes.forEach(c => {
                        const codeEl = document.createElement('div');
                        codeEl.textContent = c;
                        codeEl.style.padding = '0.25rem';
                        recoveryCodesContainer.appendChild(codeEl);
                    });

                    setupStep.style.display = 'none';
                    recoveryStep.style.display = 'block';
                } else {
                    showFeedback(data.error || 'Código incorrecto. Verifica la hora de tu dispositivo e intenta de nuevo.', false);
                }
            } catch (err) {
                showFeedback('Error de conexión con el servidor', false);
            } finally {
                submitBtn.disabled = false;
            }
        });

        btnCopyCodes.addEventListener('click', () => {
            if (generatedCodes.length === 0) return;
            navigator.clipboard.writeText(generatedCodes.join('\n')).then(() => {
                btnCopyCodes.textContent = '¡Copiados!';
                setTimeout(() => { btnCopyCodes.textContent = 'Copiar códigos'; }, 2000);
            });
        });

        btnDownloadCodes.addEventListener('click', () => {
            if (generatedCodes.length === 0) return;
            const content = 'Peak Auth - Códigos de recuperación (ROOT)\nFecha: ' + new Date().toISOString() + '\n\n' + generatedCodes.join('\n');
            const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'peak-auth-recovery-codes-root.txt';
            a.click();
            URL.revokeObjectURL(url);
        });
    });
    })();