(() => {
    'use strict';

    const setupForm = document.getElementById('setupForm');
    if (!setupForm) return;

    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const emailError = document.getElementById('emailError');

const requirements = {
    length: { regex: /.{8,}/, el: document.getElementById('req-length') },
    upper: { regex: /[A-Z]/, el: document.getElementById('req-upper') },
    number: { regex: /[0-9]/, el: document.getElementById('req-number') },
    symbol: { regex: /[@$!%*?&#]/, el: document.getElementById('req-symbol') }
};

const validateEmail = (email) => {
    return String(email).toLowerCase().match(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
};

const updateRequirementUI = (id, isValid, isSubmitAttempt = false) => {
    const el = requirements[id].el;
    const checkIcon = el.querySelector('.check-icon');
    const errorIcon = el.querySelector('.error-icon');

    // Limpiar estados previos
    el.classList.remove('text-success', 'text-danger', 'is-valid', 'is-invalid');
    checkIcon.classList.add('hidden');
    errorIcon.classList.add('hidden');

    if (isValid) {
        el.classList.add('text-success', 'is-valid');
        checkIcon.classList.remove('hidden');
    } else if (isSubmitAttempt) {
        el.classList.add('text-danger', 'is-invalid');
        errorIcon.classList.remove('hidden');
    }
};

passwordInput.addEventListener('input', () => {
    const wrapper = passwordInput.closest('.password-toggle-wrapper');
    if (wrapper) {
        if (passwordInput.value.length > 0) {
            wrapper.classList.add('has-value');
        } else {
            wrapper.classList.remove('has-value');
        }
    }

    let allValid = true;
    Object.keys(requirements).forEach(key => {
        const isValid = passwordInput.value.match(requirements[key].regex);
        updateRequirementUI(key, isValid, false);
        if (!isValid) allValid = false;
    });

    if (allValid) {
        passwordInput.classList.remove('input-error');
    }
});

emailInput.addEventListener('input', () => {
    if (validateEmail(emailInput.value)) {
        emailError.classList.add('hidden');
        emailInput.classList.remove('input-error');
    }
});

setupForm.addEventListener('submit', (e) => {
    const isEmailValid = validateEmail(emailInput.value);
    let isPasswordValid = true;

    Object.keys(requirements).forEach(key => {
        const isValid = passwordInput.value.match(requirements[key].regex);
        updateRequirementUI(key, isValid, true);
        if (!isValid) isPasswordValid = false;
    });

    if (!isEmailValid) {
        emailError.classList.remove('hidden');
        emailInput.classList.add('input-error');
        e.preventDefault();
    }

    if (!isPasswordValid) {
        passwordInput.classList.add('input-error');
        e.preventDefault();
    }
});
})();