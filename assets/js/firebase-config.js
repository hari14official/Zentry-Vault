// Firebase Configuration Fetcher for Zentry Vault
// This script fetches the Firebase config from the backend to keep keys out of Git.

(async function() {
    try {
        const response = await fetch('/api/firebase-config');
        const firebaseConfig = await response.json();

        // Initialize Firebase (Compat)
        firebase.initializeApp(firebaseConfig);
        
        // Make services globally available
        globalThis.auth = firebase.auth();
        globalThis.db = firebase.firestore();
        
        console.log("Firebase initialized successfully from backend config.");
        
        // Dispatch event so other scripts know Firebase is ready
        globalThis.dispatchEvent(new Event('firebase-ready'));
    } catch (error) {
        console.error("Failed to initialize Firebase:", error);
    }
})();

// Global Helper to handle Firebase Errors
function handleFirebaseError(error) {
    console.error("Firebase Error:", error.code, error.message);
    
    switch (error.code) {
        case 'auth/unauthorized-domain':
            return "This domain is not authorized. Please add '" + globalThis.location.hostname + "' to Authorized Domains in Firebase Console > Authentication > Settings.";
        case 'auth/billing-not-enabled':
            return "Phone authentication requires a 'Blaze' (Pay-as-you-go) plan in the Firebase Console to send SMS in certain regions.";
        case 'auth/invalid-phone-number':
            return "Invalid format. Please use international format (e.g., +1 234 567 8901).";
        case 'auth/invalid-login-credentials':
            return "Invalid email or password. Please check your credentials and try again.";
        case 'auth/network-request-failed':
            return "Network error. Please check your internet connection.";
        case 'auth/too-many-requests':
            return "Too many attempts. Please try again later.";
        case 'auth/user-not-found':
            return "No account found with this email.";
        case 'auth/wrong-password':
            return "Incorrect password. Please try again.";
        default:
            return error.message;
    }
}

// Global Helper to format Phone Number
function formatPhoneNumber(phone) {
    let clean = phone.replaceAll(/\D/g, '');
    if (!phone.startsWith('+')) {
        return '+' + clean;
    }
    return '+' + clean;
}
