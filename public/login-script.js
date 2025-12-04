// ============================================
// KONFIGURASI
// ============================================
const API_BASE_URL = window.location.origin;

// ============================================
// DOM ELEMENTS
// ============================================
const loginBtn = document.getElementById('loginBtn');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const toast = document.getElementById('toast');
const toastMessage = document.getElementById('toastMessage');
const toastIcon = document.getElementById('toastIcon');
const toastClose = document.getElementById('toastClose');

// ============================================
// EVENT LISTENERS
// ============================================
loginBtn.addEventListener('click', handleLogin);
usernameInput.addEventListener('keypress', (e) => e.key === 'Enter' && handleLogin());
passwordInput.addEventListener('keypress', (e) => e.key === 'Enter' && handleLogin());
toastClose.addEventListener('click', hideToast);

// ============================================
// AUTHENTICATION FUNCTIONS
// ============================================
async function handleLogin() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();

    if (!username || !password) {
        showToast('Username dan password harus diisi!', 'error');
        return;
    }

    try {
        showToast('Login...', 'info');

        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // Save to localStorage
            localStorage.setItem('cookieCheckerToken', data.data.token);
            localStorage.setItem('cookieCheckerUser', data.data.username);

            showToast('Login berhasil! Mengalihkan...', 'success');

            // Redirect to dashboard after short delay
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 1500);
        } else {
            showToast(data.message || 'Login gagal!', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast('Error: ' + error.message, 'error');
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function showToast(message, type = 'info') {
    // Set content
    toastMessage.textContent = message;

    // Set type styling
    toast.className = 'toast ' + type;

    // Set icon based on type
    switch(type) {
        case 'success':
            toastIcon.className = 'fas fa-check-circle';
            break;
        case 'error':
            toastIcon.className = 'fas fa-exclamation-circle';
            break;
        case 'warning':
            toastIcon.className = 'fas fa-exclamation-triangle';
            break;
        default:
            toastIcon.className = 'fas fa-info-circle';
    }

    // Show toast
    toast.classList.add('show');

    // Auto-hide after 5 seconds
    setTimeout(hideToast, 5000);
}

function hideToast() {
    toast.classList.remove('show');
}

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    // Check if already logged in
    const token = localStorage.getItem('cookieCheckerToken');
    if (token) {
        // Redirect to dashboard if already logged in
        window.location.href = 'index.html';
    }

    // Focus on username input
    usernameInput.focus();

    // Show welcome message
    setTimeout(() => {
        showToast('Masukkan kredensial login Anda', 'info');
    }, 500);
});
