from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pyotp
import uuid
import os
import threading
import traceback
import requests as http_requests
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

import base64
from Crypto.Cipher import AES, DES3, ARC4, Salsa20
from Crypto.Util.Padding import pad, unpad
import hashlib

app = Flask(__name__)
CORS(app)

# In-memory stores for demonstration
encrypted_shares = {}   # Maps share_id -> file/text info, keys, and owner_contact (user 1)
otps_in_transit = {}    # Maps phone/email -> generated OTP

# --- EMAIL CONFIG (Gmail API over HTTPS – uses your existing Google account, no new signup) ---
GMAIL_CLIENT_ID     = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET", "")
GMAIL_REFRESH_TOKEN = os.getenv("GMAIL_REFRESH_TOKEN", "")
SENDER_EMAIL        = os.getenv("SENDER_EMAIL", "haridonsines2005@gmail.com")
SENDER_NAME         = os.getenv("SENDER_NAME", "Zentry Vault")


def _get_gmail_access_token() -> str:
    """Exchange the long-lived refresh token for a short-lived access token."""
    resp = http_requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id":     GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "refresh_token": GMAIL_REFRESH_TOKEN,
            "grant_type":    "refresh_token",
        },
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _perform_send(recipient: str, subject: str, body: str, is_html=False):
    """Send email via Gmail API (HTTPS port 443 – always open on Render, no new accounts needed)."""
    if not GMAIL_CLIENT_ID or not GMAIL_CLIENT_SECRET or not GMAIL_REFRESH_TOKEN:
        print("[EMAIL] => SKIPPING: GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN not set.")
        print(f"[EMAIL] => LOG FOR {recipient}: {body[:200]}...")
        return

    try:
        print(f"[EMAIL] => Sending to {recipient} via Gmail API...")

        # Build a MIME email and base64-encode it (Gmail API requires this format)
        msg = MIMEText(body, "html" if is_html else "plain")
        msg["To"]      = recipient
        msg["From"]    = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg["Subject"] = subject
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode()

        access_token = _get_gmail_access_token()

        response = http_requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"raw": raw_message},
            timeout=15
        )
        if response.status_code == 200:
            print(f"[EMAIL] => SUCCESS: id={response.json().get('id')}")
        else:
            print(f"[EMAIL] => FAILED: HTTP {response.status_code} – {response.text}")
    except Exception as e:
        print(f"[EMAIL] => FAILED: {str(e)}")
        traceback.print_exc()



EMAIL_BANNER_B64_CACHE = ""

def get_banner_base64():
    global EMAIL_BANNER_B64_CACHE
    if not EMAIL_BANNER_B64_CACHE:
        try:
            banner_path = os.path.join(app.root_path, 'assets', 'images', 'email-banner.png')
            if os.path.exists(banner_path):
                with open(banner_path, "rb") as image_file:
                    EMAIL_BANNER_B64_CACHE = base64.b64encode(image_file.read()).decode('utf-8')
        except Exception as e:
            print(f"[BANNER] => FAILED TO LOAD: {str(e)}")
    return EMAIL_BANNER_B64_CACHE

def mock_send_email(email, otp, purpose='encrypt', tool_name="Zentry Vault Tool"):
    """ Wraps the actual email sending in a thread to prevent blocking the UI. """
    threading.Thread(target=send_email_task, args=(email, otp, purpose, tool_name)).start()

def send_email_task(email, otp, purpose='encrypt', tool_name="Zentry Vault Tool"):
    banner_base64 = get_banner_base64()
    img_html = f'<div style="text-align: center; margin-bottom: 30px;"><img src="data:image/png;base64,{banner_base64}" alt="Zentry Vault" style="width: 100%; max-width: 600px; height: auto; display: block; margin: 0 auto; border-radius: 8px;"></div>' if banner_base64 else ""

    if purpose == 'share-access':
        # Decrypt Template
        msg_body = f"""
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 25px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;">
            {img_html}
            <p style="font-size: 16px;">Dear User,</p>
            <p style="font-size: 16px;">A user is requesting access to your encrypted keys in Zentry Vault. <strong>{tool_name}</strong> security tool. To complete this action and ensure the security of your account/data, please use the following One-Time Password (OTP) valid for the next 5 minutes:</p>
            
            <div style="background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                <span style="font-size: 28px; font-weight: 800; color: #4f8ef5; letter-spacing: 4px;">🔑Verification Code: {otp}</span>
            </div>
            
            <p style="font-size: 15px;">Please enter this code directly into the application prompt. Do not share this code with anyone. Our security team will never ask for your OTP.</p>
            <p style="font-size: 15px;">⚠️<strong>IMPORTANT: Only share this code if you trust the person requesting access.</strong> 🚫Do not share this with anyone else.</p>
            
            <p style="font-size: 15px; color: #64748b; margin-top: 25px;">If you did not initiate this action, please ignore this email and secure your account immediately.</p>
            
            <div style="margin-top: 35px; padding-top: 20px; border-top: 1px solid #edf2f7; text-align: center; color: #718096; font-size: 13px;">
                <p style="font-weight: 700; color: #1a202c; margin-bottom: 5px;">Zentry Vault</p>
                <p>If you require additional assistance, our support team is always available to help at <a href="mailto:support@zentryvault.com" style="color: #4f8ef5; text-decoration: none;">support@zentryvault.com</a> or through the support page on the website.</p>
                <p style="margin-top: 15px; font-weight: 600;">Thank you,<br>The Zentry Vault Team</p>
            </div>
        </div>
        """
        subject = "Zentry Vault: Key Access OTP"
    else:
        # Encrypt Template
        msg_body = f"""
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 25px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;">
            {img_html}
            <p style="font-size: 16px;">Dear User,</p>
            <p style="font-size: 16px;">A request was made to Encrypt content using the <strong>{tool_name}</strong> security tool. To complete this action and ensure the security of your account/data, please use the following One-Time Password (OTP) valid for the next 5 minutes:</p>
            
            <div style="background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                <span style="font-size: 20px; font-weight: 800; color: #4f8ef5; letter-spacing: 4px;">🔑Verification Code: {otp}</span>
            </div>
            
            <p style="font-size: 15px;">Please enter this code directly into the application prompt. 🚫Do not share this code with anyone. Our security team will never ask for your OTP.</p>
            <p style="font-size: 15px; color: #64748b; margin-top: 25px;">⚠️If you did not initiate this action, please ignore this email and secure your account immediately.</p>
            
            <div style="margin-top: 35px; padding-top: 20px; border-top: 1px solid #edf2f7; text-align: center; color: #718096; font-size: 13px;">
                <p style="font-weight: 700; color: #1a202c; margin-bottom: 5px;">Zentry Vault</p>
                <p>If you require additional assistance, our support team is always available to help at <a href="mailto:support@zentryvault.com" style="color: #4f8ef5; text-decoration: none;">support@zentryvault.com</a> or through the support page on the website.</p>
                <p style="margin-top: 15px; font-weight: 600;">Thank you,<br>The Zentry Vault Team</p>
            </div>
        </div>
        """
        subject = "Zentry Vault: Encryption OTP"

    _perform_send(email, subject, msg_body, is_html=True)

def mock_send_notification_email(email, event_type):
    """ Wraps the actual notification email sending in a thread. """
    threading.Thread(target=send_notification_email_task, args=(email, event_type)).start()

def send_notification_email_task(email, event_type):
    subject = "Zentry Vault Account Alert"
    content = "Welcome! Your Zentry Vault account has been created successfully." if event_type == 'signup' else "Security Alert: New login detected."
    _perform_send(email, subject, content)

@app.route('/api/request-otp', methods=['POST'])
def request_otp():
    data = request.json
    contact_val = data.get('contact') 
    tool_name = data.get('tool_name', 'Zentry Vault Tool')
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=300)
    otp = totp.now()
    otps_in_transit[contact_val] = {'otp': otp, 'secret': secret}
    mock_send_email(contact_val, otp, purpose='encrypt', tool_name=tool_name)
    return jsonify({"success": True, "message": "OTP sent successfully"})

def get_crypto_key(keys_list, length, algo=None):
    if algo == 'TripleDES' and len(keys_list) == 3:
        # Use direct concatenation of the three 8-character keys as requested
        # Each DES key must be 8 bytes
        return "".join(keys_list).encode()[:length]
    combined = "".join(keys_list).encode()
    return hashlib.sha256(combined).digest()[:length]

@app.route('/api/verify-and-encrypt', methods=['POST'])
def verify_and_encrypt():
    data = request.json
    contact_val = data.get('contact')
    otp_entered = data.get('otp')
    keys = data.get('keys', [])
    plaintext = data.get('plaintext', "")
    algo = data.get('algo', 'AES')

    stored = otps_in_transit.get(contact_val)
    if not stored or stored['otp'] != otp_entered:
        return jsonify({"success": False, "message": "Invalid OTP"}), 400

    try:
        if algo == 'TripleDES':
            # SECURITY NOTE: TripleDES is a legacy algorithm provided for compatibility/educational tools.
            # Stronger alternatives like AES are recommended for modern security applications.
            real_key = get_crypto_key(keys, 24, algo='TripleDES')
            cipher = DES3.new(real_key, DES3.MODE_CBC)
            iv = cipher.iv
            ct_bytes = cipher.encrypt(pad(plaintext.encode(), 8))
        elif algo == 'RC4':
            # SECURITY NOTE: RC4 is a legacy stream cipher with known vulnerabilities.
            # It is provided here as part of a comprehensive crypto-toolkit.
            real_key = get_crypto_key(keys, 16)
            cipher = ARC4.new(real_key)
            ct_bytes = cipher.encrypt(plaintext.encode())
            iv = b"" # RC4 does not use IV
        elif algo == 'Rabbit':
            # Using Salsa20 as an efficient equivalent stream cipher for 'Rabbit'
            real_key = get_crypto_key(keys, 32)
            cipher = Salsa20.new(key=real_key)
            ct_bytes = cipher.encrypt(plaintext.encode())
            iv = cipher.nonce # Handled as IV for transport
        else:
            real_key = get_crypto_key(keys, 32)
            cipher = AES.new(real_key, AES.MODE_CBC)
            iv = cipher.iv
            ct_bytes = cipher.encrypt(pad(plaintext.encode(), 16))
        
        encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": f"Encryption error: {str(e)}"}), 500

    share_token = str(uuid.uuid4())[:12]
    encrypted_shares[share_token] = {
        'owner_contact': contact_val,
        'encrypted_data': encrypted_data,
        'keys': keys,
        'algo': algo,
        'file_name': data.get('file_name', 'Zentry Secure Content')
    }
    return jsonify({"success": True, "encrypted_data": encrypted_data, "share_id": share_token})

@app.route('/api/encrypt-direct', methods=['POST'])
def encrypt_direct():
    """ Called if User is authenticated via Google. Skips OTP. """
    data = request.json
    contact_val = data.get('contact')
    keys = data.get('keys', [])
    plaintext = data.get('plaintext', "")
    algo = data.get('algo', 'AES')

    if not contact_val:
        return jsonify({"success": False, "message": "User email required for sharing"}), 400

    print(f"DEBUG: Encryption started for {contact_val} using {algo}")

    try:
        if algo == 'TripleDES':
            # Compatibility mode for legacy systems
            real_key = get_crypto_key(keys, 24, algo='TripleDES')
            cipher = DES3.new(real_key, DES3.MODE_CBC)
            iv = cipher.iv
            ct_bytes = cipher.encrypt(pad(plaintext.encode(), 8))
        elif algo == 'RC4':
            # Compatibility mode for legacy systems
            real_key = get_crypto_key(keys, 16)
            cipher = ARC4.new(real_key)
            ct_bytes = cipher.encrypt(plaintext.encode())
            iv = b""
        elif algo == 'Rabbit':
            real_key = get_crypto_key(keys, 32)
            cipher = Salsa20.new(key=real_key)
            ct_bytes = cipher.encrypt(plaintext.encode())
            iv = cipher.nonce
        else:
            real_key = get_crypto_key(keys, 32)
            cipher = AES.new(real_key, AES.MODE_CBC)
            iv = cipher.iv
            ct_bytes = cipher.encrypt(pad(plaintext.encode(), 16))
        
        encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": f"Encryption error: {str(e)}"}), 500

    share_token = str(uuid.uuid4())[:12]
    encrypted_shares[share_token] = {
        'owner_contact': contact_val,
        'encrypted_data': encrypted_data,
        'keys': keys,
        'algo': algo,
        'file_name': data.get('file_name', 'Zentry Secure Content')
    }
    return jsonify({"success": True, "encrypted_data": encrypted_data, "share_id": share_token})

@app.route('/api/request-decrypt-otp', methods=['POST'])
def request_decrypt_otp():
    data = request.json
    share_id = data.get('share_id')
    share_info = encrypted_shares.get(share_id)
    if not share_info:
        print(f"DEBUG Error: Share ID {share_id} not found in {list(encrypted_shares.keys())}")
        return jsonify({"success": False, "message": "Invalid Share ID"}), 404
    owner_contact = share_info['owner_contact']
    
    print(f"DEBUG: Requesting OTP for share_id {share_id}. Owner is {owner_contact}")
    
    # Generate OTP
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=300)
    otp = totp.now()
    otps_in_transit[owner_contact] = {'otp': otp, 'secret': secret}
    
    # Send to OWNER (User 1)
    print(f"DEBUG: Attempting to send OTP {otp} to {owner_contact}")
    tool_name = share_info.get('file_name', 'Zentry Vault Tool')
    mock_send_email(owner_contact, otp, purpose='share-access', tool_name=tool_name)
    return jsonify({"success": True, "message": f"6-digit OTP sent to {owner_contact} G-mail account."})

@app.route('/api/share-info/<share_id>', methods=['GET'])
def get_share_info(share_id):
    share_info = encrypted_shares.get(share_id)
    if not share_info:
        return jsonify({"success": False, "message": "Share link expired or invalid"}), 404
    return jsonify({
        "success": True, 
        "encrypted_data": share_info['encrypted_data'],
        "algo": share_info['algo']
    })

@app.route('/api/verify-and-decrypt', methods=['POST'])
def verify_and_decrypt():
    data = request.json
    share_id = data.get('share_id')
    otp_entered = data.get('otp')
    share_info = encrypted_shares.get(share_id)
    if not share_info:
        return jsonify({"success": False, "message": "Invalid Share Link"}), 404
    owner_contact = share_info['owner_contact']
    stored = otps_in_transit.get(owner_contact)
    if not stored or stored['otp'] != otp_entered:
        return jsonify({"success": False, "message": "Invalid OTP"}), 400
    try:
        raw = base64.b64decode(share_info['encrypted_data'])
        if share_info['algo'] == 'TripleDES':
            # Compatibility mode for legacy systems
            iv, ct = raw[:8], raw[8:]
            real_key = get_crypto_key(share_info['keys'], 24, algo='TripleDES')
            cipher = DES3.new(real_key, DES3.MODE_CBC, iv=iv)
            decrypted_str = unpad(cipher.decrypt(ct), 8).decode('utf-8')
        elif share_info['algo'] == 'RC4':
            # Compatibility mode for legacy systems
            real_key = get_crypto_key(share_info['keys'], 16)
            cipher = ARC4.new(real_key)
            decrypted_str = cipher.decrypt(raw).decode('utf-8')
        elif share_info['algo'] == 'Rabbit':
            iv, ct = raw[:8], raw[8:] # Salsa20 nonce is 8 bytes
            real_key = get_crypto_key(share_info['keys'], 32)
            cipher = Salsa20.new(key=real_key, nonce=iv)
            decrypted_str = cipher.decrypt(ct).decode('utf-8')
        else:
            iv, ct = raw[:16], raw[16:]
            real_key = get_crypto_key(share_info['keys'], 32)
            cipher = AES.new(real_key, AES.MODE_CBC, iv=iv)
            decrypted_str = unpad(cipher.decrypt(ct), 16).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": f"Decryption error: {str(e)}"}), 500
    return jsonify({
        "success": True, 
        "decrypted_data": decrypted_str,
        "keys": share_info['keys'],
        "algo": share_info['algo']
    })

@app.route('/api/request-reset-otp', methods=['POST'])
def request_reset_otp():
    data = request.json
    email = data.get('email')
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=300)
    otp = totp.now()
    otps_in_transit[email] = {'otp': otp, 'secret': secret}
    mock_send_email(email, otp)
    return jsonify({"success": True, "message": "OTP sent to email."})

@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.json
    email = data.get('email')
    otp_entered = data.get('otp')
    stored = otps_in_transit.get(email)
    if not stored or stored['otp'] != otp_entered:
        return jsonify({"success": False, "message": "Invalid OTP"}), 400
    return jsonify({"success": True})

@app.route('/api/send-notification', methods=['POST'])
def send_notification():
    data = request.json
    mock_send_notification_email(data.get('email'), data.get('type'))
    return jsonify({"success": True})

@app.route('/api/firebase-config', methods=['GET'])
def get_firebase_config():
    return jsonify({
        "apiKey": os.getenv("FIREBASE_API_KEY"),
        "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
        "projectId": os.getenv("FIREBASE_PROJECT_ID"),
        "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
        "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
        "appId": os.getenv("FIREBASE_APP_ID"),
        "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID")
    })

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(BASE_DIR, path)

if __name__ == '__main__':
    # Use dynamic port from environment for Render/Cloud compatibility
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
