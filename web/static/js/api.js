(function () {
    'use strict';

    function copyCode(button) {
        const codeBlock = button.closest('.code-block');
        const code = codeBlock ? codeBlock.querySelector('code') : null;
        if (!code || !navigator.clipboard) {
            if (typeof window.showToast === 'function') {
                window.showToast('No se pudo copiar el código', 'error');
            }
            return;
        }

        navigator.clipboard.writeText(code.innerText).then(function () {
            const label = button.querySelector('span');
            const previousText = label ? label.textContent : '';

            if (label) {
                label.textContent = '¡Copiado!';
            }
            button.classList.add('api-copy-success');

            window.setTimeout(function () {
                if (label) {
                    label.textContent = previousText;
                }
                button.classList.remove('api-copy-success');
            }, 2000);
        }).catch(function () {
            if (typeof window.showToast === 'function') {
                window.showToast('No se pudo copiar el código', 'error');
            }
        });
    }

    document.addEventListener('click', function (event) {
        const target = event.target;
        if (!(target instanceof Element)) {
            return;
        }

        const button = target.closest('[data-action="copy-code"]');
        if (button) {
            copyCode(button);
        }
    });
}());
