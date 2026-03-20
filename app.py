from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pyotp
import uuid
import os
import smtplib
import ssl
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
from Crypto.Cipher import AES, DES3, ARC4, Salsa20
from Crypto.Util.Padding import pad, unpad
import hashlib
import traceback
import socket
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


app = Flask(__name__)
CORS(app)

# In-memory stores for demonstration
encrypted_shares = {}   # Maps share_id -> file/text info, keys, and owner_contact (user 1)
otps_in_transit = {}    # Maps phone/email -> generated OTP

# --- EMAIL CONFIG ---
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")


def _perform_smtp_send(recipient, subject, body):
    """ Internal helper to perform SMTP send on port 587 with STARTTLS (Render-compatible). """
    # Guard: check if credentials are configured
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print(f"[SMTP] => SKIPPING: SENDER_EMAIL or SENDER_PASSWORD env vars are NOT set on this server.")
        print(f"[SMTP] => LOG FOR {recipient}: {body}")
        return

    try:
        smtp_server = "smtp.gmail.com"
        port = 587  # STARTTLS port — works on Render free tier (port 465 SSL is often blocked)
        context = ssl.create_default_context()

        # Force IPv4 to avoid "Network is unreachable" errors caused by IPv6 on cloud servers
        print(f"[SMTP] => Resolving {smtp_server} to IPv4...")
        addr_info = socket.getaddrinfo(smtp_server, port, socket.AF_INET, socket.SOCK_STREAM)
        ipv4_address = addr_info[0][4][0]

        print(f"[SMTP] => Connecting to {smtp_server} ({ipv4_address}):{port} via STARTTLS (30s timeout)...")
        with smtplib.SMTP(ipv4_address, port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)

            msg = MIMEMultipart()
            msg['From'] = SENDER_EMAIL
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            server.send_message(msg)
        print(f"[SMTP] => SUCCESS: Email sent to {recipient}!")
    except smtplib.SMTPAuthenticationError:
        print(f"[SMTP] => FAILED: Authentication error. Check SENDER_EMAIL and SENDER_PASSWORD (use an App Password, not your Gmail login password).")
        traceback.print_exc()
    except smtplib.SMTPException as e:
        print(f"[SMTP] => FAILED (SMTP error): {str(e)}")
        traceback.print_exc()
    except Exception as e:
        print(f"[SMTP] => FAILED (general error): {str(e)}")
        traceback.print_exc()

def mock_send_email(email, otp, purpose='encrypt'):
    """ Wraps the actual SMTP sending in a thread to prevent blocking the UI. """
    threading.Thread(target=send_email_task, args=(email, otp, purpose)).start()

def send_email_task(email, otp, purpose='encrypt'):
    if purpose == 'share-access':
        msg_body = f"A user is requesting access to your encrypted keys in Zentry Vault.\n\nYour OTP for granting access is: {otp}\n\nIMPORTANT: Only share this code if you trust the person requesting access. Do not share this with anyone else."
        subject = "Zentry Vault: Key Access OTP"
    else:
        msg_body = f"This is the mail from Zentry Vault to Encrypt your data.\n\nYour OTP for Encryption is: {otp}\n\nNote: don't share this to anyone."
        subject = "Zentry Vault: Encryption OTP"
    
    _perform_smtp_send(email, subject, msg_body)

def mock_send_notification_email(email, event_type):
    """ Wraps the actual notification SMTP sending in a thread. """
    threading.Thread(target=send_notification_email_task, args=(email, event_type)).start()

def send_notification_email_task(email, event_type):
    subject = "Zentry Vault Account Alert"
    content = "Welcome! Your Zentry Vault account has been created successfully." if event_type == 'signup' else "Security Alert: New login detected."
    _perform_smtp_send(email, subject, content)

@app.route('/api/request-otp', methods=['POST'])
def request_otp():
    data = request.json
    contact_val = data.get('contact') 
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, interval=300)
    otp = totp.now()
    otps_in_transit[contact_val] = {'otp': otp, 'secret': secret}
    mock_send_email(contact_val, otp, purpose='encrypt')
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

    share_token = str(uuid.uuid4())[:8]
    encrypted_shares[share_token] = {
        'owner_contact': contact_val,
        'encrypted_data': encrypted_data,
        'keys': keys,
        'algo': algo
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

    share_token = str(uuid.uuid4())[:8]
    encrypted_shares[share_token] = {
        'owner_contact': contact_val,
        'encrypted_data': encrypted_data,
        'keys': keys,
        'algo': algo
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
    mock_send_email(owner_contact, otp, purpose='share-access')
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
