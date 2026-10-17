
const settingsRoot = document.getElementById('settings-root');
const csrfToken = settingsRoot ? settingsRoot.dataset.csrfToken : '';

function initSettingsPage() {
    // 1. Manejo de tabs estilo GitHub
    const tabs = document.querySelectorAll('.settings-tab-btn');
    const panels = document.querySelectorAll('.settings-panel');

    function switchTab(targetTab) {
        tabs.forEach(t => {
            const isActive = t.getAttribute('data-tab') === targetTab;
            t.classList.toggle('active', isActive);
        });

        panels.forEach(p => {
            p.classList.toggle('hidden', p.id !== 'panel-' + targetTab);
        });
    }
    window.switchSettingsTab = switchTab;

    tabs.forEach(t => {
        t.addEventListener('click', () => {
            const tabName = t.getAttribute('data-tab');
            window.location.hash = tabName;
            switchTab(tabName);
        });
    });

    if (window.location.hash) {
        const hash = window.location.hash.substring(1);
        if (['profile', 'security', 'sessions', 'applications'].includes(hash)) {
            switchTab(hash);
        }
    } else {
        switchTab('profile');
    }

    // 1.1 Helpers de feedback seguro
    function showFeedback(el, message, isSuccess) {
        if (!el) return;
        el.textContent = message;
        el.classList.add('is-visible');
        el.classList.toggle('is-success', isSuccess);
        el.classList.toggle('is-error', !isSuccess);
    }

    // 1.2 Formulario de Perfil
    const formProfile = document.getElementById('form-profile');
    const profileFeedback = document.getElementById('profile-feedback');
    const avatarInput = document.getElementById('profile-avatar-url');
    const avatarFileInput = document.getElementById('profile-avatar-file');
    const btnSelectAvatar = document.getElementById('btn-select-avatar');
    const avatarFileName = document.getElementById('avatar-file-name');

    // Gestión de subida de avatar de perfil

    if (btnSelectAvatar && avatarFileInput) {
        btnSelectAvatar.addEventListener('click', () => {
            avatarFileInput.click();
        });
    }

    function updateAvatarPreview(src) {
        const container = document.getElementById('profile-avatar-container');
        if (!container) return;
        let img = document.getElementById('profile-avatar-preview');
        if (!img) {
            container.replaceChildren();
            img = document.createElement('img');
            img.id = 'profile-avatar-preview';
            img.alt = 'Avatar';
            img.className = 'settings-profile-avatar-image';
            container.appendChild(img);
        }
        img.src = src;
    }

    if (avatarInput) {
        avatarInput.addEventListener('input', () => {
            const url = avatarInput.value.trim();
            if (url) {
                updateAvatarPreview(url);
            }
        });
    }

    if (avatarFileInput) {
        avatarFileInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (file) {
                if (file.size > 5 * 1024 * 1024) {
                    showFeedback(profileFeedback, 'El archivo excede el tamaño máximo permitido (5 MB)', false);
                    avatarFileInput.value = '';
                    if (avatarFileName) {
                        avatarFileName.textContent = 'Ningún archivo seleccionado';
                        avatarFileName.classList.remove('has-file');
                    }
                    return;
                }
                if (avatarFileName) {
                    avatarFileName.textContent = file.name;
                    avatarFileName.classList.add('has-file');
                }
                const reader = new FileReader();
                reader.onload = (ev) => {
                    if (ev.target && ev.target.result) {
                        updateAvatarPreview(ev.target.result);
                    }
                };
                reader.readAsDataURL(file);
            } else if (avatarFileName) {
                avatarFileName.textContent = 'Ningún archivo seleccionado';
                avatarFileName.classList.remove('has-file');
            }
        });
    }

    if (formProfile) {
        formProfile.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btn-save-profile');
            if (btn) btn.disabled = true;

            try {
                const formData = new FormData(formProfile);
                const res = await fetch('/admin/settings/profile', {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    },
                    body: formData
                });
                const data = await res.json();
                if (res.ok) {
                    showFeedback(profileFeedback, data.message || 'Perfil actualizado exitosamente', true);
                    const firstName = document.getElementById('profile-first-name').value.trim();
                    const lastName = document.getElementById('profile-last-name').value.trim();
                    const fullName = [firstName, lastName].filter(Boolean).join(' ');
                    if (fullName) {
                        const nameDisplay = document.getElementById('profile-name-display');
                        if (nameDisplay) nameDisplay.textContent = fullName;
                        const sidebarUserName = document.getElementById('sidebar-user-name');
                        if (sidebarUserName) sidebarUserName.textContent = fullName;
                        const navUserEmail = document.querySelector('.navbar-user-email');
                        if (navUserEmail) navUserEmail.textContent = fullName;
                        const avatarFallback = document.getElementById('profile-avatar-fallback');
                        if (avatarFallback && firstName) avatarFallback.textContent = firstName.charAt(0).toUpperCase();
                        const sidebarFallback = document.getElementById('sidebar-avatar-fallback');
                        if (sidebarFallback && firstName) sidebarFallback.textContent = firstName.charAt(0).toUpperCase();
                    }
                    if (data.avatar_url) {
                        if (avatarInput) avatarInput.value = data.avatar_url;
                        updateAvatarPreview(data.avatar_url);
                        const sidebarAvatarContainer = document.getElementById('sidebar-avatar-container');
                        if (sidebarAvatarContainer) {
                            sidebarAvatarContainer.replaceChildren();
                            const sideImg = document.createElement('img');
                            sideImg.id = 'sidebar-avatar-img';
                            sideImg.src = data.avatar_url;
                            sideImg.alt = 'Avatar';
                            sideImg.className = 'settings-avatar-image';
                            sidebarAvatarContainer.appendChild(sideImg);
                        }
                        if (avatarFileInput) avatarFileInput.value = '';
                        if (avatarFileName) {
                            avatarFileName.textContent = 'Ningún archivo seleccionado';
                            avatarFileName.classList.remove('has-file');
                        }
                    }
                } else {
                    showFeedback(profileFeedback, data.error || 'Error al actualizar el perfil', false);
                }
            } catch (err) {
                showFeedback(profileFeedback, 'Error de conexión con el servidor', false);
            } finally {
                if (btn) btn.disabled = false;
            }
        });
    }

    // Formulario de Cambio de Contraseña
    const formPassword = document.getElementById('form-password');
    const passwordFeedback = document.getElementById('password-feedback');

    if (formPassword) {
        formPassword.addEventListener('submit', async (e) => {
            e.preventDefault();
            const pwdNew = document.getElementById('pwd-new').value;
            const pwdConfirm = document.getElementById('pwd-confirm').value;

            if (pwdNew !== pwdConfirm) {
                showFeedback(passwordFeedback, 'La nueva contraseña y su confirmación no coinciden', false);
                return;
            }

            const btn = document.getElementById('btn-save-password');
            if (btn) btn.disabled = true;

            try {
                const formData = new FormData(formPassword);
                const res = await fetch('/admin/settings/password', {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    },
                    body: formData
                });
                const data = await res.json();
                if (res.ok) {
                    showFeedback(passwordFeedback, data.message || 'Contraseña actualizada exitosamente', true);
                    formPassword.reset();
                } else {
                    showFeedback(passwordFeedback, data.error || 'Error al actualizar la contraseña', false);
                }
            } catch (err) {
                showFeedback(passwordFeedback, 'Error de conexión con el servidor', false);
            } finally {
                if (btn) btn.disabled = false;
            }
        });
    }

    // 1.4 Selector de fecha de nacimiento personalizado
    function initCustomDatePicker() {
        const hiddenInput = document.getElementById('profile-birth-date');
        const displayInput = document.getElementById('profile-birth-date-display');
        const btnOpen = document.getElementById('btn-open-datepicker');
        const popup = document.getElementById('peak-datepicker-popup');
        if (!hiddenInput || !displayInput || !popup) return;

        const monthNames = [
            'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
            'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
        ];
        const weekdayNames = ['Lu', 'Ma', 'Mi', 'Ju', 'Vi', 'Sá', 'Do'];

        function parseISODate(val) {
            if (!val) return null;
            const parts = val.split('-');
            if (parts.length !== 3) return null;
            const y = parseInt(parts[0], 10);
            const m = parseInt(parts[1], 10) - 1;
            const d = parseInt(parts[2], 10);
            if (isNaN(y) || isNaN(m) || isNaN(d)) return null;
            return new Date(y, m, d);
        }

        function formatDisplay(d) {
            if (!d) return '';
            const day = String(d.getDate()).padStart(2, '0');
            const month = monthNames[d.getMonth()].toLowerCase();
            const year = d.getFullYear();
            return `${day} de ${month} de ${year}`;
        }

        function toISODate(d) {
            if (!d) return '';
            const y = d.getFullYear();
            const m = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            return `${y}-${m}-${day}`;
        }

        let selectedDate = parseISODate(hiddenInput.value);
        if (selectedDate) {
            displayInput.value = formatDisplay(selectedDate);
        }

        const today = new Date();
        const currentYear = today.getFullYear();
        let viewYear = selectedDate ? selectedDate.getFullYear() : 2000;
        let viewMonth = selectedDate ? selectedDate.getMonth() : 0;

        function renderCalendar() {
            popup.replaceChildren();

            const firstDayOfMonth = new Date(viewYear, viewMonth, 1);
            let startDay = firstDayOfMonth.getDay() - 1;
            if (startDay === -1) startDay = 6;

            const daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
            const daysInPrevMonth = new Date(viewYear, viewMonth, 0).getDate();

            // Header
            const header = document.createElement('div');
            header.className = 'peak-datepicker-header';

            const prevBtn = document.createElement('button');
            prevBtn.type = 'button';
            prevBtn.className = 'peak-datepicker-nav-btn';
            prevBtn.id = 'dp-prev-month';
            prevBtn.title = 'Mes anterior';
            prevBtn.setAttribute('aria-label', 'Mes anterior');
            const prevSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            prevSvg.setAttribute('class', 'settings-icon-sm');
            prevSvg.setAttribute('fill', 'none');
            prevSvg.setAttribute('stroke', 'currentColor');
            prevSvg.setAttribute('viewBox', '0 0 24 24');
            const prevPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            prevPath.setAttribute('stroke-linecap', 'round');
            prevPath.setAttribute('stroke-linejoin', 'round');
            prevPath.setAttribute('stroke-width', '2');
            prevPath.setAttribute('d', 'M15 19l-7-7 7-7');
            prevSvg.appendChild(prevPath);
            prevBtn.appendChild(prevSvg);

            const selectsDiv = document.createElement('div');
            selectsDiv.className = 'peak-datepicker-selects';

            const monthSelect = document.createElement('select');
            monthSelect.className = 'peak-datepicker-select';
            monthSelect.id = 'dp-select-month';
            monthSelect.setAttribute('aria-label', 'Seleccionar mes');
            monthNames.forEach((m, idx) => {
                const opt = document.createElement('option');
                opt.value = String(idx);
                opt.textContent = m;
                if (idx === viewMonth) opt.selected = true;
                monthSelect.appendChild(opt);
            });

            const yearSelect = document.createElement('select');
            yearSelect.className = 'peak-datepicker-select';
            yearSelect.id = 'dp-select-year';
            yearSelect.setAttribute('aria-label', 'Seleccionar año');
            for (let y = currentYear; y >= 1920; y--) {
                const opt = document.createElement('option');
                opt.value = String(y);
                opt.textContent = String(y);
                if (y === viewYear) opt.selected = true;
                yearSelect.appendChild(opt);
            }

            selectsDiv.appendChild(monthSelect);
            selectsDiv.appendChild(yearSelect);

            const nextBtn = document.createElement('button');
            nextBtn.type = 'button';
            nextBtn.className = 'peak-datepicker-nav-btn';
            nextBtn.id = 'dp-next-month';
            nextBtn.title = 'Mes siguiente';
            nextBtn.setAttribute('aria-label', 'Mes siguiente');
            const nextSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            nextSvg.setAttribute('class', 'settings-icon-sm');
            nextSvg.setAttribute('fill', 'none');
            nextSvg.setAttribute('stroke', 'currentColor');
            nextSvg.setAttribute('viewBox', '0 0 24 24');
            const nextPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            nextPath.setAttribute('stroke-linecap', 'round');
            nextPath.setAttribute('stroke-linejoin', 'round');
            nextPath.setAttribute('stroke-width', '2');
            nextPath.setAttribute('d', 'M9 5l7 7-7 7');
            nextSvg.appendChild(nextPath);
            nextBtn.appendChild(nextSvg);

            header.appendChild(prevBtn);
            header.appendChild(selectsDiv);
            header.appendChild(nextBtn);
            popup.appendChild(header);

            // Weekdays
            const weekdaysDiv = document.createElement('div');
            weekdaysDiv.className = 'peak-datepicker-weekdays';
            weekdayNames.forEach(w => {
                const wDiv = document.createElement('div');
                wDiv.className = 'peak-datepicker-weekday';
                wDiv.textContent = w;
                weekdaysDiv.appendChild(wDiv);
            });
            popup.appendChild(weekdaysDiv);

            // Days grid
            const grid = document.createElement('div');
            grid.className = 'peak-datepicker-grid';

            for (let i = startDay - 1; i >= 0; i--) {
                const dayNum = daysInPrevMonth - i;
                const dBtn = document.createElement('button');
                dBtn.type = 'button';
                dBtn.className = 'peak-datepicker-day other-month';
                dBtn.textContent = String(dayNum);
                dBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    viewMonth--;
                    if (viewMonth < 0) {
                        viewMonth = 11;
                        viewYear--;
                    }
                    selectedDate = new Date(viewYear, viewMonth, dayNum);
                    hiddenInput.value = toISODate(selectedDate);
                    displayInput.value = formatDisplay(selectedDate);
                    closePopup();
                });
                grid.appendChild(dBtn);
            }

            for (let day = 1; day <= daysInMonth; day++) {
                const isToday = (viewYear === today.getFullYear() && viewMonth === today.getMonth() && day === today.getDate());
                const isSelected = selectedDate && (viewYear === selectedDate.getFullYear() && viewMonth === selectedDate.getMonth() && day === selectedDate.getDate());
                const btn = document.createElement('button');
                btn.type = 'button';
                let classes = 'peak-datepicker-day';
                if (isSelected) classes += ' selected';
                if (isToday) classes += ' today';
                btn.className = classes;
                btn.textContent = String(day);
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    selectedDate = new Date(viewYear, viewMonth, day);
                    hiddenInput.value = toISODate(selectedDate);
                    displayInput.value = formatDisplay(selectedDate);
                    closePopup();
                });
                grid.appendChild(btn);
            }

            const totalRendered = startDay + daysInMonth;
            const remaining = (totalRendered % 7 === 0) ? 0 : 7 - (totalRendered % 7);
            for (let i = 1; i <= remaining; i++) {
                const dayNum = i;
                const dBtn = document.createElement('button');
                dBtn.type = 'button';
                dBtn.className = 'peak-datepicker-day other-month';
                dBtn.textContent = String(dayNum);
                dBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    viewMonth++;
                    if (viewMonth > 11) {
                        viewMonth = 0;
                        viewYear++;
                    }
                    selectedDate = new Date(viewYear, viewMonth, dayNum);
                    hiddenInput.value = toISODate(selectedDate);
                    displayInput.value = formatDisplay(selectedDate);
                    closePopup();
                });
                grid.appendChild(dBtn);
            }
            popup.appendChild(grid);

            // Footer
            const footer = document.createElement('div');
            footer.className = 'peak-datepicker-footer';

            const clearBtn = document.createElement('button');
            clearBtn.type = 'button';
            clearBtn.id = 'dp-btn-clear';
            clearBtn.className = 'peak-btn peak-btn-secondary settings-date-action';
            clearBtn.textContent = 'Borrar';
            clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                selectedDate = null;
                hiddenInput.value = '';
                displayInput.value = '';
                closePopup();
            });

            const todayBtn = document.createElement('button');
            todayBtn.type = 'button';
            todayBtn.id = 'dp-btn-today';
            todayBtn.className = 'peak-btn peak-btn-secondary settings-date-action';
            todayBtn.textContent = 'Hoy';
            todayBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                selectedDate = new Date(today.getFullYear(), today.getMonth(), today.getDate());
                viewYear = today.getFullYear();
                viewMonth = today.getMonth();
                hiddenInput.value = toISODate(selectedDate);
                displayInput.value = formatDisplay(selectedDate);
                closePopup();
            });

            footer.appendChild(clearBtn);
            footer.appendChild(todayBtn);
            popup.appendChild(footer);

            prevBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                viewMonth--;
                if (viewMonth < 0) {
                    viewMonth = 11;
                    viewYear--;
                }
                renderCalendar();
            });

            nextBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                viewMonth++;
                if (viewMonth > 11) {
                    viewMonth = 0;
                    viewYear++;
                }
                renderCalendar();
            });

            monthSelect.addEventListener('change', (e) => {
                e.stopPropagation();
                viewMonth = parseInt(e.target.value, 10);
                renderCalendar();
            });

            yearSelect.addEventListener('change', (e) => {
                e.stopPropagation();
                viewYear = parseInt(e.target.value, 10);
                renderCalendar();
            });
        }

        function openPopup() {
            if (selectedDate) {
                viewYear = selectedDate.getFullYear();
                viewMonth = selectedDate.getMonth();
            } else {
                viewYear = 2000;
                viewMonth = 0;
            }
            renderCalendar();
            popup.classList.remove('hidden');
        }

        function closePopup() {
            popup.classList.add('hidden');
        }

        function togglePopup(e) {
            if (e) {
                e.preventDefault();
                e.stopPropagation();
            }
            if (!popup.classList.contains('hidden')) {
                closePopup();
            } else {
                openPopup();
            }
        }

        displayInput.addEventListener('click', togglePopup);

        if (btnOpen) {
            btnOpen.addEventListener('click', togglePopup);
        }

        popup.addEventListener('click', (e) => {
            e.stopPropagation();
        });

        document.addEventListener('click', (e) => {
            if (!popup.classList.contains('hidden')) {
                if (!popup.contains(e.target) && e.target !== displayInput && (!btnOpen || !btnOpen.contains(e.target))) {
                    closePopup();
                }
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !popup.classList.contains('hidden')) {
                closePopup();
            }
        });
    }

    initCustomDatePicker();

    // 2. Manejo de métodos de autenticación multi-factor (2FA)
    const palette = window.PeakPalette || { error: '#b91c1c', warning: '#e5e843', secondary: '#3075ad', success: '#10b981' };
    const themeConfig = window.getPeakThemeConfig ? window.getPeakThemeConfig() : { background: '#fff', color: '#0f172a' };
    let currentRecoveryCodesLeft = 0;

    // 2.1 TOTP (Aplicación Authenticator)
    const btnConfigTotp = document.getElementById('btn-config-totp');
    const btnDisableTotp = document.getElementById('btn-disable-totp');

    if (btnConfigTotp) {
        btnConfigTotp.addEventListener('click', async () => {
            try {
                await setupTotp(palette, themeConfig);
                showToast('Aplicación autenticadora configurada exitosamente', 'success');
                await loadMfaSummary();
            } catch (err) {
                if (err && err.message && err.message !== 'Operación cancelada por el usuario') {
                    showToast(err.message, 'error');
                }
            }
        });
    }

    if (btnDisableTotp) {
        btnDisableTotp.addEventListener('click', async () => {
            const confirm = await PeakModal.fire({
                title: '¿Desactivar aplicación autenticadora?',
                text: 'Para confirmar la desactivación de TOTP, ingresa tu contraseña actual:',
                input: 'password',
                inputPlaceholder: 'Tu contraseña actual',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Sí, desactivar',
                cancelButtonText: 'Cancelar'
            });

            if (confirm.isConfirmed && confirm.value) {
                try {
                    const res = await fetch('/api/v1/mfa/totp/disable', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrfToken
                        },
                        body: JSON.stringify({ password: confirm.value })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        showToast('Aplicación autenticadora desactivada', 'success');
                        await loadMfaSummary();
                    } else {
                        showToast(data.error || 'Error al desactivar TOTP', 'error');
                    }
                } catch (err) {
                    showToast('Error de conexión con el servidor', 'error');
                }
            }
        });
    }

    // 2.2 Quick Add Passkey y Lista Desplegable
    const btnAddPasskeyQuick = document.getElementById('btn-add-passkey-quick');
    if (btnAddPasskeyQuick) {
        btnAddPasskeyQuick.addEventListener('click', async () => {
            const namePrompt = await PeakModal.fire({
                title: 'Nueva llave de acceso (Passkey)',
                text: 'Ingresa un nombre para identificar este dispositivo o llave de seguridad:',
                input: 'text',
                inputPlaceholder: 'Ej. MacBook TouchID, YubiKey 5C, Windows Hello',
                showCancelButton: true,
                confirmButtonText: 'Continuar',
                cancelButtonText: 'Cancelar'
            });

            if (namePrompt.isConfirmed && namePrompt.value) {
                try {
                    await setupWebAuthn(palette, themeConfig, namePrompt.value.trim());
                    await loadMfaSummary();
                } catch (err) {
                    showToast(err.message || 'Error al configurar llave de acceso', 'error');
                }
            }
        });
    }

    const btnTogglePasskeysList = document.getElementById('btn-toggle-passkeys-list');
    const passkeysListContainer = document.getElementById('passkeys-inline-list-container');
    if (btnTogglePasskeysList && passkeysListContainer) {
        btnTogglePasskeysList.addEventListener('click', () => {
            const isHidden = passkeysListContainer.classList.contains('hidden');
            passkeysListContainer.classList.toggle('hidden', !isHidden);
            btnTogglePasskeysList.textContent = isHidden ? '(ocultar lista)' : '(ver lista)';
        });
    }

    // 2.3 Códigos de recuperación
    const btnManageRecovery = document.getElementById('btn-manage-recovery');
    if (btnManageRecovery) {
        btnManageRecovery.addEventListener('click', async () => {
            await openRecoveryCodesModal(currentRecoveryCodesLeft);
        });
    }

    async function openRecoveryCodesModal(remainingCount) {
        const countMsg = (remainingCount !== undefined && remainingCount > 0)
            ? `Actualmente dispones de <strong class="settings-modal-emphasis">${remainingCount} código${remainingCount > 1 ? 's' : ''}</strong> de recuperación sin usar.`
            : `No dispones de códigos de recuperación generados o ya has utilizado todos los anteriores.`;

        const res = await PeakModal.fire({
            title: 'Códigos de recuperación',
            html: `
                <div class="settings-recovery-modal">
                    <p>${countMsg}</p>
                    <div class="settings-recovery-security">
                        🔒 <strong>Seguridad:</strong> Los códigos de recuperación se almacenan con hash criptográfico unidireccional (bcrypt). Por seguridad, no es posible recuperarlos en texto plano una vez mostrados.
                    </div>
                    <p class="settings-recovery-note">
                        Si no recuerdas dónde los guardaste o te quedan pocos, puedes generar 10 códigos nuevos ahora mismo. Ten en cuenta que esto invalidará de forma inmediata todos los códigos generados previamente.
                    </p>
                </div>
            `,
            showCancelButton: true,
            showConfirmButton: true,
            confirmButtonText: 'Generar nuevos códigos',
            cancelButtonText: 'Cerrar',
            customClass: {
                popup: 'peak-card',
                confirmButton: 'peak-btn peak-btn-primary',
                cancelButton: 'peak-btn peak-btn-secondary'
            }
        });

        if (res.isConfirmed) {
            const confirmGen = await PeakModal.fire({
                title: '¿Generar nuevos códigos?',
                text: 'Al continuar, todos tus códigos de recuperación anteriores dejarán de funcionar permanentemente.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Sí, generar nuevos',
                cancelButtonText: 'Cancelar'
            });

            if (confirmGen.isConfirmed) {
                try {
                    const resp = await fetch('/api/v1/mfa/recovery/regenerate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrfToken
                        }
                    });
                    const data = await resp.json();
                    if (resp.ok && data.recovery_codes) {
                        await showRecoveryCodes(data.recovery_codes, palette, themeConfig, 'Nuevos códigos de recuperación');
                        await loadMfaSummary();
                    } else {
                        showToast(data.error || 'Error al generar nuevos códigos', 'error');
                    }
                } catch (err) {
                    showToast('Error de conexión con el servidor', 'error');
                }
            }
        }
    }

    // 2.4 Cargar estado de MFA reactivamente
    async function loadMfaSummary() {
        try {
            const res = await fetch('/api/v1/mfa/status');
            if (!res.ok) return;
            const data = await res.json();
            const keys = data.webauthn_keys || [];
            currentRecoveryCodesLeft = data.recovery_codes_left || 0;

            // Passkeys List
            if (btnTogglePasskeysList) {
                btnTogglePasskeysList.classList.toggle('hidden', keys.length === 0);
            }

            const passkeysInlineList = document.getElementById('passkeys-inline-list');
            if (passkeysInlineList) {
                passkeysInlineList.replaceChildren();
                keys.forEach(k => {
                    const item = document.createElement('div');
                    item.className = 'settings-passkey-item';
                    
                    const leftCol = document.createElement('div');
                    leftCol.className = 'settings-passkey-content';

                    const iconSpan = document.createElement('span');
                    iconSpan.className = 'settings-passkey-icon';
                    iconSpan.textContent = '🔑';

                    const detailsDiv = document.createElement('div');
                    const nameDiv = document.createElement('div');
                    nameDiv.className = 'settings-passkey-name';
                    nameDiv.textContent = k.name || 'Llave de acceso';

                    const dateDiv = document.createElement('div');
                    dateDiv.className = 'settings-passkey-date';
                    dateDiv.textContent = 'Registrada el ' + new Date(k.created_at).toLocaleDateString();

                    detailsDiv.appendChild(nameDiv);
                    detailsDiv.appendChild(dateDiv);
                    leftCol.appendChild(iconSpan);
                    leftCol.appendChild(detailsDiv);

                    const delBtn = document.createElement('button');
                    delBtn.className = 'icon-btn icon-btn-danger settings-passkey-delete';
                    delBtn.title = 'Eliminar llave de acceso';
                    delBtn.setAttribute('aria-label', 'Eliminar llave de acceso');

                    const delSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                    delSvg.setAttribute('class', 'settings-icon-delete');
                    delSvg.setAttribute('fill', 'none');
                    delSvg.setAttribute('stroke', 'currentColor');
                    delSvg.setAttribute('viewBox', '0 0 24 24');
                    const delPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                    delPath.setAttribute('stroke-linecap', 'round');
                    delPath.setAttribute('stroke-linejoin', 'round');
                    delPath.setAttribute('stroke-width', '2');
                    delPath.setAttribute('d', 'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16');
                    delSvg.appendChild(delPath);
                    delBtn.appendChild(delSvg);

                    delBtn.addEventListener('click', async () => {
                        const confirm = await PeakModal.fire({
                            title: '¿Eliminar llave de acceso?',
                            text: `¿Deseas eliminar "${k.name || 'Llave de acceso'}"?`,
                            icon: 'warning',
                            showCancelButton: true,
                            confirmButtonText: 'Sí, eliminar',
                            cancelButtonText: 'Cancelar'
                        });
                        if (confirm.isConfirmed) {
                            const dRes = await fetch('/api/v1/mfa/webauthn/credentials/' + encodeURIComponent(k.id), { method: 'DELETE' });
                            if (dRes.ok) {
                                showToast('Llave de acceso eliminada', 'success');
                                loadMfaSummary();
                            } else {
                                showToast('Error al eliminar', 'error');
                            }
                        }
                    });

                    item.appendChild(leftCol);
                    item.appendChild(delBtn);
                    passkeysInlineList.appendChild(item);
                });
            }

            // Authenticator app status & buttons
            const totpBadge = document.getElementById('totp-badge');
            if (totpBadge) {
                totpBadge.replaceChildren();
                const indicator = document.createElement('span');
                if (data.totp_configured) {
                    totpBadge.className = 'peak-badge peak-badge-success';
                    indicator.className = 'peak-badge-indicator';
                    totpBadge.appendChild(indicator);
                    totpBadge.appendChild(document.createTextNode(' Configurada'));
                } else {
                    totpBadge.className = 'peak-badge peak-badge-secondary';
                    indicator.className = 'peak-badge-indicator is-muted';
                    totpBadge.appendChild(indicator);
                    totpBadge.appendChild(document.createTextNode(' No configurada'));
                }
            }
            if (btnConfigTotp) {
                btnConfigTotp.classList.toggle('hidden', data.totp_configured);
                btnConfigTotp.textContent = 'Configurar';
            }
            if (btnDisableTotp) {
                btnDisableTotp.classList.toggle('hidden', !data.totp_configured);
            }

            // Security keys status badge
            const keysBadge = document.getElementById('keys-badge');
            if (keysBadge) {
                keysBadge.replaceChildren();
                const indicator = document.createElement('span');
                if (keys.length > 0) {
                    keysBadge.className = 'peak-badge peak-badge-success';
                    indicator.className = 'peak-badge-indicator';
                    keysBadge.appendChild(indicator);
                    keysBadge.appendChild(document.createTextNode(` ${keys.length} configurada${keys.length > 1 ? 's' : ''}`));
                } else {
                    keysBadge.className = 'peak-badge peak-badge-secondary';
                    indicator.className = 'peak-badge-indicator is-muted';
                    keysBadge.appendChild(indicator);
                    keysBadge.appendChild(document.createTextNode(' 0 configuradas'));
                }
            }

            // Recovery codes badge
            const recoveryBadge = document.getElementById('recovery-badge');
            if (recoveryBadge) {
                recoveryBadge.replaceChildren();
                const indicator = document.createElement('span');
                if (currentRecoveryCodesLeft > 0) {
                    recoveryBadge.className = 'peak-badge peak-badge-success';
                    indicator.className = 'peak-badge-indicator';
                    recoveryBadge.appendChild(indicator);
                    recoveryBadge.appendChild(document.createTextNode(` ${currentRecoveryCodesLeft} restantes`));
                } else {
                    recoveryBadge.className = 'peak-badge peak-badge-warning';
                    indicator.className = 'peak-badge-indicator';
                    recoveryBadge.appendChild(indicator);
                    recoveryBadge.appendChild(document.createTextNode(' No generados'));
                }
            }

        } catch (e) {
            console.error('Error cargando estado MFA', e);
        }
    }

    loadMfaSummary();

    // 3. Revocación de sesiones individuales
    document.querySelectorAll('.btn-revoke-session').forEach(btn => {
        btn.addEventListener('click', async () => {
            const sessionId = btn.getAttribute('data-id');
            const confirm = await PeakModal.fire({
                title: '¿Cerrar sesión?',
                text: 'Se cerrará la sesión en este dispositivo de forma remota.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Sí, cerrar sesión',
                cancelButtonText: 'Cancelar'
            });

            if (confirm.isConfirmed) {
                const res = await fetch('/api/v1/user/sessions/' + sessionId, { method: 'DELETE' });
                if (res.ok) {
                    showToast('Sesión revocada exitosamente', 'success');
                    window.location.reload();
                } else {
                    showToast('Error al revocar sesión', 'error');
                }
            }
        });
    });

    // 4. Revocación de todas las demás sesiones
    const revokeOthersBtn = document.getElementById('btn-revoke-others');
    if (revokeOthersBtn) {
        const otherSessions = document.querySelectorAll('.session-card[data-is-current="false"]');
        if (otherSessions.length === 0) {
            revokeOthersBtn.disabled = true;
            revokeOthersBtn.setAttribute('title', 'No hay otras sesiones activas');
        }

        revokeOthersBtn.addEventListener('click', async () => {
            if (revokeOthersBtn.disabled) return;
            const confirm = await PeakModal.fire({
                title: '¿Cerrar todas las demás sesiones?',
                text: 'Se desconectarán todos los demás dispositivos y aplicaciones excepto esta ventana.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Sí, cerrar todas las demás',
                cancelButtonText: 'Cancelar'
            });

            if (confirm.isConfirmed) {
                const currentSessionEl = document.querySelector('.session-card[data-is-current="true"]');
                const currentSessionId = currentSessionEl ? parseInt(currentSessionEl.getAttribute('data-id'), 10) : 0;

                const res = await fetch('/api/v1/user/sessions/revoke-others', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_session_id: currentSessionId })
                });
                if (res.ok) {
                    showToast('Todas las demás sesiones fueron cerradas', 'success');
                    window.location.reload();
                } else {
                    showToast('Error al revocar otras sesiones', 'error');
                }
            }
        });
    }

    // 5. Revocación de aplicaciones autorizadas
    document.querySelectorAll('.btn-revoke-app').forEach(btn => {
        btn.addEventListener('click', async () => {
            const clientId = btn.getAttribute('data-client-id');
            const confirm = await PeakModal.fire({
                title: '¿Revocar acceso?',
                text: 'La aplicación perderá acceso inmediatamente y sus sesiones serán invalidadas.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Sí, revocar acceso',
                cancelButtonText: 'Cancelar'
            });

            if (confirm.isConfirmed) {
                const res = await fetch('/api/v1/user/applications/' + encodeURIComponent(clientId), { method: 'DELETE' });
                if (res.ok) {
                    showToast('Acceso revocado exitosamente', 'success');
                    window.location.reload();
                } else {
                    showToast('Error al revocar aplicación', 'error');
                }
            }
        });
    });
}

if (document.readyState === 'loading') {

document.addEventListener('DOMContentLoaded', initSettingsPage);
} else {
    initSettingsPage();
}
