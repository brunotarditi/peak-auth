const setupForm = document.getElementById('setupForm');
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
    el.classList.remove('text-success', 'text-danger', 'text-slate-400', 'text-emerald-500', 'text-rose-500', 'text-rose-600');
    checkIcon.classList.add('hidden');
    errorIcon.classList.add('hidden');

    if (isValid) {
        el.classList.add('text-success');
        checkIcon.classList.remove('hidden');
    } else if (isSubmitAttempt) {
        el.classList.add('text-danger');
        errorIcon.classList.remove('hidden');
    } else {
        el.classList.add('text-slate-400');
    }
};

passwordInput.addEventListener('input', () => {
    let allValid = true;
    Object.keys(requirements).forEach(key => {
        const isValid = passwordInput.value.match(requirements[key].regex);
        updateRequirementUI(key, isValid, false);
        if (!isValid) allValid = false;
    });

    if (allValid) {
        passwordInput.classList.remove('border-danger', 'ring-danger');
    }
});

emailInput.addEventListener('input', () => {
    if (validateEmail(emailInput.value)) {
        emailError.classList.add('hidden');
        emailInput.classList.remove('border-danger', 'ring-danger');
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
        emailError.classList.add('text-danger');
        emailInput.classList.add('border-danger', 'ring-danger');
        e.preventDefault();
    }

    if (!isPasswordValid) {
        passwordInput.classList.add('border-danger', 'ring-danger');
        e.preventDefault();
    }
});