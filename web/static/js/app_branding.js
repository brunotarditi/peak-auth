/**
 * Peak Auth - Application Branding & Themes (Live Preview & AJAX Uploads)
 * 100% Vanilla JS modular
 */

(function () {
    const container = document.getElementById('appBrandingContainer');
    if (!container) return;

    const appId = container.getAttribute('data-app-id');
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || '';

    // Elements
    const primaryColorPicker = document.getElementById('primaryColorPicker');
    const primaryColorInput = document.getElementById('primaryColorInput');
    const btnOpenColorPicker = document.getElementById('btnOpenColorPicker');
    const colorSwatchIndicator = document.getElementById('colorSwatchIndicator');
    const presetBtns = document.querySelectorAll('.color-preset-btn');

    const logoFileInput = document.getElementById('logoFileInput');
    const btnSelectLogo = document.getElementById('btnSelectLogo');
    const logoFileName = document.getElementById('logoFileName');
    const logoUrlInput = document.getElementById('logoUrlInput');
    const logoThumbImg = document.getElementById('logoThumbImg');
    const logoUploadStatus = document.getElementById('logoUploadStatus');
    const previewLogoImg = document.getElementById('previewLogoImg');

    const faviconFileInput = document.getElementById('faviconFileInput');
    const btnSelectFavicon = document.getElementById('btnSelectFavicon');
    const faviconFileName = document.getElementById('faviconFileName');
    const faviconUrlInput = document.getElementById('faviconUrlInput');
    const faviconThumbImg = document.getElementById('faviconThumbImg');
    const faviconUploadStatus = document.getElementById('faviconUploadStatus');

    const customTitleInput = document.getElementById('customTitleInput');
    const customSubtitleInput = document.getElementById('customSubtitleInput');
    const previewTitleText = document.getElementById('previewTitleText');
    const previewSubtitleText = document.getElementById('previewSubtitleText');

    const termsUrlInput = document.getElementById('termsUrlInput');
    const privacyUrlInput = document.getElementById('privacyUrlInput');
    const previewTermsLink = document.getElementById('previewTermsLink');
    const previewPrivacyLink = document.getElementById('previewPrivacyLink');
    const previewLegalDot = document.getElementById('previewLegalDot');

    const previewContainer = document.getElementById('previewContainer');
    const previewCard = document.getElementById('previewCard');
    const previewDynamicStyles = document.getElementById('previewDynamicStyles');
    const previewThemeToggle = document.getElementById('previewThemeToggle');
    const previewThemeLabel = document.getElementById('previewThemeLabel');
    const previewThemeIcon = document.getElementById('previewThemeIcon');

    const btnResetTheme = document.getElementById('btnResetTheme');
    const resetThemeForm = document.getElementById('resetThemeForm');

    // Utility: Calculate Luminance and Contrast
    function getContrastTextColor(hex) {
        let clean = hex.replace('#', '');
        if (clean.length === 3) {
            clean = clean.split('').map(c => c + c).join('');
        }
        const r = parseInt(clean.substring(0, 2), 16) / 255;
        const g = parseInt(clean.substring(2, 4), 16) / 255;
        const b = parseInt(clean.substring(4, 6), 16) / 255;

        const toLinear = (c) => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
        const lum = 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
        return lum > 0.4 ? '#0f172a' : '#ffffff';
    }

    function adjustColorBrightness(hex, percent) {
        let clean = hex.replace('#', '');
        if (clean.length === 3) {
            clean = clean.split('').map(c => c + c).join('');
        }
        let num = parseInt(clean, 16);
        let amt = Math.round(2.55 * percent);
        let R = (num >> 16) + amt;
        let B = ((num >> 8) & 0x00FF) + amt;
        let G = (num & 0x0000FF) + amt;

        return '#' + (0x1000000 + (R < 255 ? (R < 1 ? 0 : R) : 255) * 0x10000 +
            (B < 255 ? (B < 1 ? 0 : B) : 255) * 0x100 +
            (G < 255 ? (G < 1 ? 0 : G) : 255)).toString(16).slice(1);
    }

    // Update dynamic preview CSS
    function updateBrandColor(hex) {
        if (!/^#([0-9A-Fa-f]{3}){1,2}$/.test(hex)) return;

        const brand500 = hex;
        const brand600 = adjustColorBrightness(hex, -15);
        const brand400 = adjustColorBrightness(hex, 15);
        const contrastText = getContrastTextColor(hex);

        if (colorSwatchIndicator) {
            colorSwatchIndicator.style.background = brand500;
        }

        const css = `
            #previewContainer, #previewCard {
                --brand-400: ${brand400} !important;
                --brand-500: ${brand500} !important;
                --brand-600: ${brand600} !important;
                --brand-contrast-text: ${contrastText} !important;
                --ring-focus: ${brand500}33 !important;
            }
            #previewActionBtn {
                background: ${brand500} !important;
                color: ${contrastText} !important;
            }
            #previewActionBtn:hover {
                background: ${brand600} !important;
            }
        `;
        if (previewDynamicStyles) {
            previewDynamicStyles.textContent = css;
        }
    }

    // Color picker synchronization
    if (primaryColorPicker && primaryColorInput) {
        primaryColorPicker.addEventListener('input', function () {
            primaryColorInput.value = primaryColorPicker.value.toUpperCase();
            updateBrandColor(primaryColorPicker.value);
        });

        primaryColorInput.addEventListener('input', function () {
            let val = primaryColorInput.value.trim();
            if (!val.startsWith('#') && val.length > 0) {
                val = '#' + val;
            }
            if (/^#([0-9A-Fa-f]{3}){1,2}$/.test(val)) {
                primaryColorPicker.value = val;
                updateBrandColor(val);
            }
        });

        if (btnOpenColorPicker) {
            btnOpenColorPicker.addEventListener('click', function () {
                if (typeof primaryColorPicker.showPicker === 'function') {
                    primaryColorPicker.showPicker();
                } else {
                    primaryColorPicker.click();
                }
            });
        }

        // Initialize preview with current color
        updateBrandColor(primaryColorPicker.value);
    }

    // Color presets
    presetBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            const color = btn.getAttribute('data-color');
            if (color) {
                primaryColorPicker.value = color;
                primaryColorInput.value = color.toUpperCase();
                updateBrandColor(color);
            }
        });
    });

    // Modern file upload buttons
    if (btnSelectLogo && logoFileInput) {
        btnSelectLogo.addEventListener('click', () => logoFileInput.click());
    }
    if (btnSelectFavicon && faviconFileInput) {
        btnSelectFavicon.addEventListener('click', () => faviconFileInput.click());
    }


    // Real-time title & subtitle updates
    if (customTitleInput && previewTitleText) {
        customTitleInput.addEventListener('input', function () {
            const text = customTitleInput.value.trim();
            previewTitleText.textContent = text || 'Iniciar sesión';
        });
    }

    if (customSubtitleInput && previewSubtitleText) {
        customSubtitleInput.addEventListener('input', function () {
            const text = customSubtitleInput.value.trim();
            previewSubtitleText.textContent = text || 'Continuar hacia tu app';
        });
    }

    // Real-time logo URL input updates
    if (logoUrlInput && previewLogoImg) {
        logoUrlInput.addEventListener('input', function () {
            const url = logoUrlInput.value.trim();
            const targetUrl = url || '/static/img/logo.svg';
            previewLogoImg.src = targetUrl;
            if (logoThumbImg) logoThumbImg.src = targetUrl;
        });
    }

    // Real-time favicon URL input updates
    if (faviconUrlInput && faviconThumbImg) {
        faviconUrlInput.addEventListener('input', function () {
            const url = faviconUrlInput.value.trim();
            faviconThumbImg.src = url || '/static/img/favicon.png';
        });
    }

    // Real-time legal links
    function updateLegalLinks() {
        const terms = termsUrlInput?.value.trim();
        const privacy = privacyUrlInput?.value.trim();

        if (previewTermsLink) previewTermsLink.style.display = terms ? 'inline' : 'none';
        if (previewPrivacyLink) previewPrivacyLink.style.display = privacy ? 'inline' : 'none';
        if (previewLegalDot) previewLegalDot.style.display = (terms && privacy) ? 'inline' : 'none';
    }

    if (termsUrlInput) termsUrlInput.addEventListener('input', updateLegalLinks);
    if (privacyUrlInput) privacyUrlInput.addEventListener('input', updateLegalLinks);

    // Instant AJAX Logo Upload
    if (logoFileInput) {
        logoFileInput.addEventListener('change', async function () {
            const file = logoFileInput.files[0];
            if (!file) return;

            if (logoFileName) {
                const sizeKb = Math.round(file.size / 1024);
                logoFileName.textContent = `${file.name} (${sizeKb} KB)`;
                logoFileName.style.fontStyle = 'normal';
                logoFileName.style.color = 'var(--text-main)';
            }

            if (file.size > 5 * 1024 * 1024) {
                alert('El archivo supera el límite de 5 MB.');
                logoFileInput.value = '';
                if (logoFileName) logoFileName.textContent = 'Archivo excede límite de 5 MB';
                return;
            }

            const formData = new FormData();
            formData.append('logo', file);
            formData.append('csrf_token', csrfToken);

            if (logoUploadStatus) {
                logoUploadStatus.textContent = 'Subiendo imagen...';
                logoUploadStatus.style.color = 'var(--brand-500)';
            }

            try {
                const res = await fetch(`/admin/apps/${encodeURIComponent(appId)}/branding/upload-logo`, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });
                const data = await res.json();
                if (res.ok && data.url) {
                    if (logoUrlInput) logoUrlInput.value = data.url;
                    if (logoThumbImg) logoThumbImg.src = data.url;
                    if (previewLogoImg) previewLogoImg.src = data.url;
                    if (logoUploadStatus) {
                        logoUploadStatus.textContent = '✓ Logo subido y guardado';
                        logoUploadStatus.style.color = 'var(--emerald-600)';
                    }
                } else {
                    throw new Error(data.error || 'Error al subir logo');
                }
            } catch (err) {
                if (logoUploadStatus) {
                    logoUploadStatus.textContent = `✕ Error: ${err.message}`;
                    logoUploadStatus.style.color = 'var(--rose-600)';
                }
            }
        });
    }

    // Instant AJAX Favicon Upload
    if (faviconFileInput) {
        faviconFileInput.addEventListener('change', async function () {
            const file = faviconFileInput.files[0];
            if (!file) return;

            if (faviconFileName) {
                const sizeKb = Math.round(file.size / 1024);
                faviconFileName.textContent = `${file.name} (${sizeKb} KB)`;
                faviconFileName.style.fontStyle = 'normal';
                faviconFileName.style.color = 'var(--text-main)';
            }

            if (file.size > 2 * 1024 * 1024) {
                alert('El archivo supera el límite de 2 MB.');
                faviconFileInput.value = '';
                if (faviconFileName) faviconFileName.textContent = 'Archivo excede límite de 2 MB';
                return;
            }

            const formData = new FormData();
            formData.append('favicon', file);
            formData.append('csrf_token', csrfToken);

            if (faviconUploadStatus) {
                faviconUploadStatus.textContent = 'Subiendo favicon...';
                faviconUploadStatus.style.color = 'var(--brand-500)';
            }

            try {
                const res = await fetch(`/admin/apps/${encodeURIComponent(appId)}/branding/upload-favicon`, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });
                const data = await res.json();
                if (res.ok && data.url) {
                    if (faviconUrlInput) faviconUrlInput.value = data.url;
                    if (faviconThumbImg) faviconThumbImg.src = data.url;
                    if (faviconUploadStatus) {
                        faviconUploadStatus.textContent = '✓ Favicon subido y guardado';
                        faviconUploadStatus.style.color = 'var(--emerald-600)';
                    }
                } else {
                    throw new Error(data.error || 'Error al subir favicon');
                }
            } catch (err) {
                if (faviconUploadStatus) {
                    faviconUploadStatus.textContent = `✕ Error: ${err.message}`;
                    faviconUploadStatus.style.color = 'var(--rose-600)';
                }
            }
        });
    }

    // Preview Theme Toggle (Light / Dark mode testing for preview frame)
    function setPreviewTheme(isDark) {
        if (!previewContainer) return;
        if (isDark) {
            previewContainer.classList.add('preview-theme-dark');
            previewContainer.classList.remove('preview-theme-light');
            if (previewThemeIcon) previewThemeIcon.textContent = '☀️';
            if (previewThemeLabel) previewThemeLabel.textContent = 'Probar Modo Claro';
        } else {
            previewContainer.classList.add('preview-theme-light');
            previewContainer.classList.remove('preview-theme-dark');
            if (previewThemeIcon) previewThemeIcon.textContent = '🌙';
            if (previewThemeLabel) previewThemeLabel.textContent = 'Probar Modo Oscuro';
        }
    }

    // Sync initial preview theme with current user preference in admin
    const isCurrentAdminDark = document.body.classList.contains('dark') ||
        document.documentElement.classList.contains('dark') ||
        localStorage.getItem('peak_theme') === 'dark';
    
    setPreviewTheme(isCurrentAdminDark);

    if (previewThemeToggle && previewContainer) {
        previewThemeToggle.addEventListener('click', function () {
            const willBeDark = !previewContainer.classList.contains('preview-theme-dark');
            setPreviewTheme(willBeDark);
        });
    }

    // Preview Mode Toggle: Iniciar sesión vs. Registro
    const previewModeLogin = document.getElementById('previewModeLogin');
    const previewModeRegister = document.getElementById('previewModeRegister');
    const previewMockLoginForm = document.getElementById('previewMockLoginForm');
    const previewMockRegisterForm = document.getElementById('previewMockRegisterForm');

    function setPreviewViewMode(mode) {
        if (!previewMockLoginForm || !previewMockRegisterForm) return;

        if (mode === 'register') {
            previewMockLoginForm.style.display = 'none';
            previewMockRegisterForm.style.display = 'flex';

            if (previewModeLogin && previewModeRegister) {
                previewModeRegister.style.background = 'var(--bg-surface)';
                previewModeRegister.style.color = 'var(--text-main)';
                previewModeRegister.style.fontWeight = '700';
                previewModeRegister.style.boxShadow = 'var(--shadow-sm)';

                previewModeLogin.style.background = 'transparent';
                previewModeLogin.style.color = 'var(--text-muted)';
                previewModeLogin.style.fontWeight = '600';
                previewModeLogin.style.boxShadow = 'none';
            }

            if (previewTitleText) {
                previewTitleText.textContent = 'Crear cuenta';
            }
            if (previewSubtitleText) {
                previewSubtitleText.textContent = 'Ingresa tus datos para registrarte';
            }
        } else {
            previewMockLoginForm.style.display = 'flex';
            previewMockRegisterForm.style.display = 'none';

            if (previewModeLogin && previewModeRegister) {
                previewModeLogin.style.background = 'var(--bg-surface)';
                previewModeLogin.style.color = 'var(--text-main)';
                previewModeLogin.style.fontWeight = '700';
                previewModeLogin.style.boxShadow = 'var(--shadow-sm)';

                previewModeRegister.style.background = 'transparent';
                previewModeRegister.style.color = 'var(--text-muted)';
                previewModeRegister.style.fontWeight = '600';
                previewModeRegister.style.boxShadow = 'none';
            }

            if (previewTitleText) {
                previewTitleText.textContent = customTitleInput && customTitleInput.value.trim() ? customTitleInput.value.trim() : 'Iniciar sesión';
            }
            if (previewSubtitleText) {
                previewSubtitleText.textContent = customSubtitleInput && customSubtitleInput.value.trim() ? customSubtitleInput.value.trim() : 'Continuar hacia tu app';
            }
        }
    }

    if (previewModeLogin) {
        previewModeLogin.addEventListener('click', () => setPreviewViewMode('login'));
    }
    if (previewModeRegister) {
        previewModeRegister.addEventListener('click', () => setPreviewViewMode('register'));
    }

    // Reset Theme confirmation
    if (btnResetTheme && resetThemeForm) {
        btnResetTheme.addEventListener('click', function (e) {
            e.preventDefault();
            if (confirm('¿Estás seguro de que deseas restablecer el tema a los valores por defecto de Peak Auth?')) {
                resetThemeForm.submit();
            }
        });
    }
})();

