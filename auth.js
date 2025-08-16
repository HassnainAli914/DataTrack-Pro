// ===============================
// Authentication with Google Sheets backend
// ===============================

// Salted hash auth configuration
const SALT = "MySuperSecretKey_OnlyIKnow"; // keep this private

// External accounts store (fetched from Google Sheets)
let hashedAccounts = [];
let hashedAccountsLoaded = false;

// Load accounts from Google Spreadsheet
async function loadHashedAccounts() {
    if (hashedAccountsLoaded) return hashedAccounts;

    try {
        const url = "https://docs.google.com/spreadsheets/d/1BvKB2_gdI00nToCVkLlQOeH74Ndr7AScOErE4poVwVQ/gviz/tq?tqx=out:json";

        const response = await fetch(url);
        const text = await response.text();

        // Google returns JSON wrapped inside a function → clean it
        const json = JSON.parse(text.substring(47).slice(0, -2));
        const rows = json.table.rows;

        // Map columns (skip Timestamp)
        hashedAccounts = rows.map(r => ({
            usernameHash: r.c[1]?.v?.trim(),
            passwordHash: r.c[2]?.v?.trim(),
            role: r.c[3]?.v?.trim()
        }));

        hashedAccountsLoaded = true;
        console.log("Loaded accounts from sheet:", hashedAccounts);
    } catch (err) {
        console.error("Error loading accounts from Google Sheets:", err);
    }

    return hashedAccounts;
}

// SHA-256 helper (hex output)
async function sha256Hex(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Check if user is already logged in
function checkAuth() {
    const isLoggedIn = localStorage.getItem("loggedIn") === "true";
    const currentPage = (window.location.pathname.split("/").pop() || "").toLowerCase();
    const isLoginPage = currentPage === "login.html" || currentPage === "";
    const isHashGenPage = currentPage === "hashgen.html";

    if (!isLoggedIn && !isLoginPage && !isHashGenPage) {
        window.location.href = "login.html";
        return false;
    }

    if (isLoggedIn && isLoginPage) {
        window.location.href = "index.html";
        return false;
    }

    return true;
}

// Login function (salted SHA-256 verification)
async function login(username, password) {
    try {
        await loadHashedAccounts();
        const computedUserHash = await sha256Hex(String(username) + SALT);
        const computedPassHash = await sha256Hex(String(password) + SALT);

        console.log("Computed usernameHash:", computedUserHash);
        console.log("Computed passwordHash:", computedPassHash);

        // Find matching account
        const match = hashedAccounts.find(
            acc => acc.usernameHash === computedUserHash && acc.passwordHash === computedPassHash
        );

        if (match) {
            localStorage.setItem("loggedIn", "true");
            localStorage.setItem("currentUserHash", computedUserHash);
            localStorage.setItem("currentUserRole", match.role);
            return { success: true };
        }

        return { success: false, message: "Invalid username or password" };
    } catch (err) {
        console.error(err);
        return { success: false, message: "Secure hashing not supported in this context" };
    }
}

// Logout
function logout() {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("currentUserHash");
    localStorage.removeItem("currentUserRole");
    window.location.href = "login.html";
}

// Get current user info
function getCurrentUser() {
    const hash = localStorage.getItem("currentUserHash");
    const role = localStorage.getItem("currentUserRole");
    if (!hash || !role) return null;
    return { usernameHash: hash, role };
}

// Check if user is admin
function isAdmin() {
    return localStorage.getItem("currentUserRole") === "admin";
}

// Initialize authentication on page load
document.addEventListener("DOMContentLoaded", function () {
    checkAuth();

    // Handle login form
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", async function (e) {
            e.preventDefault();

            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            const errorMessage = document.getElementById("errorMessage");

            if (!username || !password) {
                errorMessage.textContent = "Please enter both username and password";
                return;
            }

            const result = await login(username, password);

            if (result && result.success) {
                errorMessage.textContent = "";
                window.location.href = "index.html";
            } else {
                errorMessage.textContent = (result && result.message) || "Login failed";
            }
        });
    }

    // Update navigation active state
    updateActiveNav();

    // Handle mobile nav link clicks
    const navLinks = document.querySelectorAll(".nav-link");
    navLinks.forEach(link => {
        link.addEventListener("click", function () {
            closeMobileMenu();
        });
    });
});

// Highlight active nav
function updateActiveNav() {
    const currentPage = window.location.pathname.split("/").pop() || "index.html";
    const navItems = document.querySelectorAll(".nav-item");

    navItems.forEach(item => {
        const link = item.querySelector(".nav-link");
        if (link) {
            const href = link.getAttribute("href");
            if (href === currentPage || (currentPage === "" && href === "index.html")) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        }
    });
}

// Mobile menu toggle
function toggleMobileMenu() {
    const mobileMenu = document.querySelector(".nav-menu");
    const mobileToggle = document.querySelector(".mobile-menu-toggle");

    if (mobileMenu && mobileToggle) {
        mobileMenu.classList.toggle("active");
        mobileToggle.classList.toggle("active");

        if (mobileMenu.classList.contains("active")) {
            document.body.style.overflow = "hidden";
        } else {
            document.body.style.overflow = "";
        }
    }
}

// Close mobile menu
function closeMobileMenu() {
    const mobileMenu = document.querySelector(".nav-menu");
    const mobileToggle = document.querySelector(".mobile-menu-toggle");

    if (mobileMenu && mobileToggle) {
        mobileMenu.classList.remove("active");
        mobileToggle.classList.remove("active");
        document.body.style.overflow = "";
    }
}

// Close menu on outside click
document.addEventListener("click", function (event) {
    const mobileMenu = document.querySelector(".nav-menu");
    const mobileToggle = document.querySelector(".mobile-menu-toggle");

    if (mobileMenu && mobileToggle &&
        !mobileMenu.contains(event.target) &&
        !mobileToggle.contains(event.target)) {
        mobileMenu.classList.remove("active");
        mobileToggle.classList.remove("active");
        document.body.style.overflow = "";
    }
});

// Reset menu on resize
window.addEventListener("resize", function () {
    if (window.innerWidth > 768) {
        closeMobileMenu();
    }
});

// Expose functions
window.auth = {
    login,
    logout,
    getCurrentUser,
    isAdmin,
    checkAuth
};
