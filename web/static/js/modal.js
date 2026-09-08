/**
 * modal.js - Sistema nativo de modales y alertas para Peak Auth.
 * Arquitectura Front-End Senior - Cero dependencias externas.
 * Construcción DOM segura (Anti-XSS), desacoplado de estilos y compatible con la API PeakModal/Swal.
 */

(() => {
    'use strict';

    // Geometría elemental para iconos vectoriales (los estilos, colores y halos viven en modal.css)
    const ICON_SVGS = {
        success: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><circle cx="24" cy="24" r="16" class="icon-badge"/><path class="icon-glyph" d="M16 24l5 5 11-11"/></svg>',
        error: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><circle cx="24" cy="24" r="16" class="icon-badge"/><path class="icon-glyph" d="M17 17l14 14m0-14L17 31"/></svg>',
        warning: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><path class="icon-badge" d="M24 8l16 28H8L24 8z"/><path class="icon-glyph" d="M24 19v8m0 4v.01"/></svg>',
        danger: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><path class="icon-badge" d="M24 8l16 28H8L24 8z"/><path class="icon-glyph" d="M24 19v8m0 4v.01"/></svg>',
        info: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><circle cx="24" cy="24" r="16" class="icon-badge"/><path class="icon-glyph" d="M24 22v10m0-15v.01"/></svg>',
        question: '<svg viewBox="0 0 48 48"><circle cx="24" cy="24" r="22" class="icon-halo"/><circle cx="24" cy="24" r="16" class="icon-badge"/><path class="icon-glyph" d="M20 20a4 4 0 118 0c0 3-4 4-4 6m0 5v.01"/></svg>'
    };

    let activeModal = null;
    let previousActiveElement = null;

    class PeakModalInstance {
        constructor(options) {
            this.options = Object.assign({
                title: '',
                text: '',
                html: '',
                icon: null,
                showConfirmButton: true,
                confirmButtonText: 'Aceptar',
                confirmButtonColor: null,
                showCancelButton: false,
                cancelButtonText: 'Cancelar',
                cancelButtonColor: null,
                reverseButtons: false,
                timer: null,
                timerProgressBar: false,
                allowOutsideClick: true,
                allowEscapeKey: true,
                preConfirm: null,
                didOpen: null,
                willClose: null,
                customClass: {},
                background: null,
                color: null
            }, options);

            this.backdrop = null;
            this.card = null;
            this.timerId = null;
            this.timerBar = null;
            this.resolvePromise = null;
            this.keyHandler = this.onKeyDown.bind(this);
        }

        open() {
            return new Promise((resolve) => {
                this.resolvePromise = resolve;

                if (activeModal) {
                    activeModal.close({ isDismissed: true, dismiss: 'replaced' });
                }
                activeModal = this;
                previousActiveElement = document.activeElement;

                this.buildDOM();
                this.mount();
            });
        }

        buildDOM() {
            const opt = this.options;

            // 1. Backdrop
            const backdrop = document.createElement('div');
            backdrop.className = 'peak-modal-backdrop';
            backdrop.setAttribute('role', 'dialog');
            backdrop.setAttribute('aria-modal', 'true');
            if (opt.title) {
                backdrop.setAttribute('aria-label', String(opt.title));
            }

            // 2. Card
            const card = document.createElement('div');
            card.className = 'peak-modal-card';
            if (opt.customClass && opt.customClass.popup) {
                card.classList.add(...opt.customClass.popup.split(' ').filter(Boolean));
            }
            if (opt.background) card.style.backgroundColor = opt.background;
            if (opt.color) card.style.color = opt.color;

            // 3. Icono
            if (opt.icon && ICON_SVGS[opt.icon]) {
                const iconWrap = document.createElement('div');
                iconWrap.className = `peak-modal-icon-wrapper peak-modal-icon-${opt.icon}`;
                iconWrap.setAttribute('aria-hidden', 'true');
                iconWrap.innerHTML = ICON_SVGS[opt.icon];
                card.appendChild(iconWrap);
            }

            // 4. Título
            if (opt.title) {
                const titleEl = document.createElement('h2');
                titleEl.className = 'peak-modal-title';
                if (opt.customClass && opt.customClass.title) {
                    titleEl.classList.add(...opt.customClass.title.split(' ').filter(Boolean));
                }
                titleEl.textContent = opt.title;
                card.appendChild(titleEl);
            }

            // 5. Contenido (Texto seguro o HTML explícito)
            if (opt.html || opt.text) {
                const contentEl = document.createElement('div');
                contentEl.className = 'peak-modal-content';
                if (opt.customClass && opt.customClass.htmlContainer) {
                    contentEl.classList.add(...opt.customClass.htmlContainer.split(' ').filter(Boolean));
                }

                if (opt.html) {
                    contentEl.innerHTML = opt.html;
                } else {
                    const p = document.createElement('p');
                    p.textContent = opt.text;
                    contentEl.appendChild(p);
                }
                card.appendChild(contentEl);
            }

            // 6. Botones de acción
            if (opt.showConfirmButton || opt.showCancelButton) {
                const actions = document.createElement('div');
                actions.className = 'peak-modal-actions';
                if (opt.reverseButtons) actions.classList.add('peak-modal-actions-reverse');
                if (opt.customClass && opt.customClass.actions) {
                    actions.classList.add(...opt.customClass.actions.split(' ').filter(Boolean));
                }

                if (opt.showCancelButton) {
                    const cancelBtn = document.createElement('button');
                    cancelBtn.type = 'button';
                    cancelBtn.className = (opt.customClass && opt.customClass.cancelButton)
                        ? opt.customClass.cancelButton
                        : 'peak-btn peak-modal-btn-cancel';
                    cancelBtn.textContent = opt.cancelButtonText;
                    if (opt.cancelButtonColor) cancelBtn.style.backgroundColor = opt.cancelButtonColor;
                    cancelBtn.addEventListener('click', () => this.close({ isConfirmed: false, isDismissed: true, dismiss: 'cancel' }));
                    actions.appendChild(cancelBtn);
                }

                if (opt.showConfirmButton) {
                    const confirmBtn = document.createElement('button');
                    confirmBtn.type = 'button';
                    confirmBtn.className = (opt.customClass && opt.customClass.confirmButton)
                        ? opt.customClass.confirmButton
                        : 'peak-btn peak-modal-btn-confirm';
                    confirmBtn.textContent = opt.confirmButtonText;
                    if (opt.confirmButtonColor) confirmBtn.style.backgroundColor = opt.confirmButtonColor;
                    confirmBtn.addEventListener('click', () => this.handleConfirm());
                    actions.appendChild(confirmBtn);
                }

                card.appendChild(actions);
            }

            // 7. Barra de temporizador
            if (opt.timer && opt.timerProgressBar) {
                const timerBar = document.createElement('div');
                timerBar.className = 'peak-modal-timer-bar';
                card.appendChild(timerBar);
                this.timerBar = timerBar;
            }

            backdrop.appendChild(card);
            this.backdrop = backdrop;
            this.card = card;

            // Click fuera del modal (Backdrop)
            backdrop.addEventListener('click', (e) => {
                if (e.target === backdrop && opt.allowOutsideClick) {
                    this.close({ isConfirmed: false, isDismissed: true, dismiss: 'backdrop' });
                }
            });
        }

        mount() {
            const scrollBarWidth = window.innerWidth - document.documentElement.clientWidth;
            if (scrollBarWidth > 0) {
                document.body.style.paddingRight = `${scrollBarWidth}px`;
            }
            document.body.classList.add('peak-modal-open');
            document.body.appendChild(this.backdrop);

            document.addEventListener('keydown', this.keyHandler);

            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    this.backdrop.classList.add('peak-modal-visible');

                    const firstInput = this.card.querySelector('input:not([type="hidden"]), select, textarea');
                    const confirmBtn = this.card.querySelector('.peak-modal-btn-confirm, .peak-btn-primary');
                    if (firstInput) {
                        firstInput.focus();
                    } else if (confirmBtn) {
                        confirmBtn.focus();
                    }

                    if (typeof this.options.didOpen === 'function') {
                        try {
                            this.options.didOpen(this.card);
                        } catch (e) {
                            console.error('Error en didOpen:', e);
                        }
                    }

                    if (this.options.timer && this.options.timer > 0) {
                        if (this.timerBar) {
                            this.timerBar.style.transitionDuration = `${this.options.timer}ms`;
                            requestAnimationFrame(() => {
                                this.timerBar.style.width = '0%';
                            });
                        }
                        this.timerId = setTimeout(() => {
                            this.close({ isConfirmed: false, isDismissed: true, dismiss: 'timer' });
                        }, this.options.timer);
                    }
                });
            });
        }

        async handleConfirm() {
            let preConfirmValue = true;
            if (typeof this.options.preConfirm === 'function') {
                try {
                    preConfirmValue = await this.options.preConfirm();
                    if (preConfirmValue === false) {
                        return;
                    }
                } catch (err) {
                    console.error('preConfirm error:', err);
                    return;
                }
            }

            this.close({
                isConfirmed: true,
                isDismissed: false,
                value: preConfirmValue
            });
        }

        onKeyDown(e) {
            if (e.key === 'Escape' && this.options.allowEscapeKey) {
                e.preventDefault();
                this.close({ isConfirmed: false, isDismissed: true, dismiss: 'esc' });
                return;
            }

            // Trampa de foco (Focus trap accesible)
            if (e.key === 'Tab') {
                const focusableElements = this.card.querySelectorAll(
                    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
                );
                if (focusableElements.length === 0) return;

                const firstElem = focusableElements[0];
                const lastElem = focusableElements[focusableElements.length - 1];

                if (e.shiftKey) {
                    if (document.activeElement === firstElem) {
                        e.preventDefault();
                        lastElem.focus();
                    }
                } else {
                    if (document.activeElement === lastElem) {
                        e.preventDefault();
                        firstElem.focus();
                    }
                }
            }
        }

        close(result = { isConfirmed: false, isDismissed: true }) {
            if (this.timerId) clearTimeout(this.timerId);
            document.removeEventListener('keydown', this.keyHandler);

            if (typeof this.options.willClose === 'function') {
                try {
                    this.options.willClose(this.card);
                } catch (e) {
                    console.error('Error en willClose:', e);
                }
            }

            if (this.backdrop) {
                this.backdrop.classList.add('peak-modal-closing');
                this.backdrop.classList.remove('peak-modal-visible');

                setTimeout(() => {
                    if (this.backdrop && this.backdrop.parentNode) {
                        this.backdrop.parentNode.removeChild(this.backdrop);
                    }
                    if (activeModal === this) {
                        activeModal = null;
                        document.body.classList.remove('peak-modal-open');
                        document.body.style.paddingRight = '';
                        if (previousActiveElement && typeof previousActiveElement.focus === 'function') {
                            previousActiveElement.focus();
                        }
                    }
                    if (this.resolvePromise) {
                        this.resolvePromise(result);
                    }
                }, 260);
            } else {
                if (this.resolvePromise) this.resolvePromise(result);
            }
        }
    }

    /**
     * API Pública PeakModal
     */
    const PeakModal = {
        fire: function(...args) {
            let options = {};
            if (args.length === 1 && typeof args[0] === 'object' && args[0] !== null) {
                options = args[0];
            } else if (args.length >= 1) {
                options.title = args[0] || '';
                options.text = args[1] || '';
                options.icon = args[2] || null;
            }

            const instance = new PeakModalInstance(options);
            return instance.open();
        },

        close: function() {
            if (activeModal) {
                activeModal.close({ isConfirmed: false, isDismissed: true, dismiss: 'close' });
            }
        },

        isVisible: function() {
            return activeModal !== null;
        }
    };

    // Exponer globalmente como PeakModal y como alias Swal de compatibilidad
    window.PeakModal = PeakModal;
    window.Swal = PeakModal;
})();
