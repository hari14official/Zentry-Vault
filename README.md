# Zentry Vault - Military-Grade Digital Security

Zentry Vault is a cutting-edge, high-performance security platform designed to provide maximum protection for your digital assets. Built with a focus on privacy and zero-knowledge architecture, it offers a comprehensive suite of encryption tools, secure sharing mechanisms, and real-time data protection.

## 🛡️ Key Features

- **Multi-Algorithm Encryption**: Powerful support for AES-256, TripleDES, RC4, and Rabbit (Salsa20) algorithms.
- **Secure File Encryption**: Protect documents, images, and audio files with local, client-side encryption.
- **OTP-Verified Access**: Built-in 6-digit Email OTP (One-Time Password) verification for critical operations.
- **Zero-Trust Architecture**: We follow the principle of "never trust, always verify." Keys are generated locally and never stored in plain text.
- **Secure Data Sharing**: Generate unique, shareable vault links that require owner approval via OTP for decryption.
- **Complete Toolkit**: Includes BIP39 Generators, Hashing tools, UUID/ULID generators, and more.
- **Modern UI**: A premium, glassmorphic design built with Tailwind CSS for a seamless user experience.

## 🛠️ Technology Stack

- **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (CDN).
- **Backend**: Python (Flask) for secure token management and OTP dispatch.
- **Database/Auth**: Firebase (Authentication & Google Sign-In, Firestore).
- **Security Logic**: `pycryptodome` (Python) and `CryptoJS` (JavaScript compatibility).
- **Infrastructure**: Designed for deployment on Render.com with Gmail API integration.

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- A Google Cloud project with Gmail API enabled (for OTP emails).
- A Firebase project for Authentication and Firestore.

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hari14official/Zentry-Vault.git
   cd Zentry-Vault
   ```

2. **Setup virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   Create a `.env` file in the root directory and add the following:
   ```env
   # Firebase Config (Shared with Frontend)
   FIREBASE_API_KEY=your-api-key
   FIREBASE_AUTH_DOMAIN=your-auth-domain
   FIREBASE_PROJECT_ID=your-project-id
   FIREBASE_STORAGE_BUCKET=your-storage-bucket
   FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   FIREBASE_APP_ID=your-app-id
   FIREBASE_MEASUREMENT_ID=your-measurement-id

   # Gmail API (for OTP sending)
   GMAIL_CLIENT_ID=your-client-id
   GMAIL_CLIENT_SECRET=your-client-secret
   GMAIL_REFRESH_TOKEN=your-refresh-token
   SENDER_EMAIL=your-verified-email@gmail.com
   SENDER_NAME=Zentry Vault
   ```

5. **Run the application**:
   ```bash
   python app.py
   ```
   Open `http://localhost:5000` in your browser.

## 🧰 Built-in Security Tools

- **Text Encryption**: AES, TripleDES, RC4, Rabbit.
- **Password Generator**: Custom entropy-based secure password generator.
- **Hash Generator**: MD5, SHA-1, SHA-256, SHA-512.
- **BIP39 Tokenizer**: Generate secure passphrases for cryptocurrency wallets.
- **UUID/ULID Tools**: Standards-compliant unique identifier generation.
- **BCrypt Hashing**: Secure password hashing for developers.

## ⚖️ Security Notice

Zentry Vault provides both modern (AES) and legacy (TripleDES, RC4) cryptography. While legacy algorithms are included for research and compatibility, we **highly recommend** using AES-256 for all sensitive data.

## 📄 License

Copyright © 2025-2026 Zentry Vault Ltd. All rights reserved.

---

Crafted with 💙 by [hari14official](https://github.com/hari14official)
