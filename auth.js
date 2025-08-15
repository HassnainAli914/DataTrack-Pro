// Salted hash auth configuration
const SALT = "MySuperSecretKey_OnlyIKnow"; // Private salt

// External accounts store (JSON). Each entry: { usernameHash, passwordHash, role }
let hashedAccounts = [];
let hashedAccountsLoaded = false;

async function loadHashedAccounts() {
    if (hashedAccountsLoaded) return hashedAccounts;
    try {
        const response = await fetch('hashedAccounts.json', { cache: 'no-store' });
        if (response.ok) {
            const data = await response.json();
            if (Array.isArray(data)) {
                hashedAccounts = data;
                hashedAccountsLoaded = true;
            } else {
                console.error('hashedAccounts.json is not an array.');
            }
        } else {
            console.error('Failed to fetch hashedAccounts.json:', response.status);
        }
    } catch (err) {
        console.error('Error loading hashedAccounts.json:', err);
    }
    return hashedAccounts;
}

// SHA-256 helper (hex output)
async function sha256Hex(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Check if user is already logged in
function checkAuth() {
    const isLoggedIn = localStorage.getItem('loggedIn') === 'true';
    const currentPage = (window.location.pathname.split('/').pop() || '').toLowerCase();
    const isLoginPage = currentPage === 'login.html' || currentPage === '';
    const isHashGenPage = currentPage === 'hashgen.html';

    if (!isLoggedIn && !isLoginPage && !isHashGenPage) {
        window.location.href = 'login.html';
        return false;
    }

    if (isLoggedIn && isLoginPage) {
        window.location.href = 'index.html';
        return false;
    }

    return true;
}

// Login function (salted SHA-256 verification)
async function login(username, password) {
    try {
        // Ensure accounts are loaded
        await loadHashedAccounts();
        const computedUserHash = await sha256Hex(String(username) + SALT);
        const computedPassHash = await sha256Hex(String(password) + SALT);

		// Find matching account by hashes
		const match = hashedAccounts.find(acc => acc.usernameHash === computedUserHash && acc.passwordHash === computedPassHash);
		if (match) {
			localStorage.setItem('loggedIn', 'true');
			// Avoid storing plaintext username; store hash and role only
			localStorage.setItem('currentUserHash', computedUserHash);
			localStorage.setItem('currentUserRole', match.role);
			return { success: true };
		}
		return { success: false, message: 'Invalid username or password' };
    } catch (err) {
        return { success: false, message: 'Secure hashing not supported in this context' };
    }
}

// Logout function
function logout() {
    localStorage.removeItem('loggedIn');
    localStorage.removeItem('currentUserHash');
    localStorage.removeItem('currentUserRole');
    window.location.href = 'login.html';
}

// Get current user
function getCurrentUser() {
    const hash = localStorage.getItem('currentUserHash');
    const role = localStorage.getItem('currentUserRole');
    if (!hash || !role) return null;
    return { usernameHash: hash, role };
}

// Check if current user is admin
function isAdmin() {
    const role = localStorage.getItem('currentUserRole');
    return role === 'admin';
}

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    
    // Handle login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('errorMessage');
            
            if (!username || !password) {
                errorMessage.textContent = 'Please enter both username and password';
                return;
            }
            
            const result = await login(username, password);
            
            if (result && result.success) {
                errorMessage.textContent = '';
                window.location.href = 'index.html';
            } else {
                errorMessage.textContent = (result && result.message) || 'Login failed';
            }
        });
    }
    
    // Update navigation active state
    updateActiveNav();
    
    // Add click event listeners to navigation links to close mobile menu
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            // Close mobile menu when a link is clicked
            closeMobileMenu();
        });
    });
});

// Update active navigation item
function updateActiveNav() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        const link = item.querySelector('.nav-link');
        if (link) {
            const href = link.getAttribute('href');
            if (href === currentPage || (currentPage === '' && href === 'index.html')) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        }
    });
}

// Mobile menu functionality
function toggleMobileMenu() {
    const mobileMenu = document.querySelector('.nav-menu');
    const mobileToggle = document.querySelector('.mobile-menu-toggle');
    
    if (mobileMenu && mobileToggle) {
        mobileMenu.classList.toggle('active');
        mobileToggle.classList.toggle('active');
        
        // Prevent body scroll when menu is open
        if (mobileMenu.classList.contains('active')) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
    }
}

// Close mobile menu when clicking on a link
function closeMobileMenu() {
    const mobileMenu = document.querySelector('.nav-menu');
    const mobileToggle = document.querySelector('.mobile-menu-toggle');
    
    if (mobileMenu && mobileToggle) {
        mobileMenu.classList.remove('active');
        mobileToggle.classList.remove('active');
        document.body.style.overflow = '';
    }
}

// Close mobile menu when clicking outside
document.addEventListener('click', function(event) {
    const mobileMenu = document.querySelector('.nav-menu');
    const mobileToggle = document.querySelector('.mobile-menu-toggle');
    
    if (mobileMenu && mobileToggle && 
        !mobileMenu.contains(event.target) && 
        !mobileToggle.contains(event.target)) {
        mobileMenu.classList.remove('active');
        mobileToggle.classList.remove('active');
        document.body.style.overflow = '';
    }
});

// Close mobile menu on window resize
window.addEventListener('resize', function() {
    if (window.innerWidth > 768) {
        closeMobileMenu();
    }
});

// Export functions for use in other scripts
window.auth = {
    login,
    logout,
    getCurrentUser,
    isAdmin,
    checkAuth
};
