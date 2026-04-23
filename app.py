from flask import Flask, request, jsonify, send_file, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from supabase import create_client
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import cv2, numpy as np, os, io, base64, secrets, hashlib, logging

load_dotenv()

# ── Logging (audit trail) ──────────────────────────────
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "30 per hour"]
)

supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from password using PBKDF2-SHA256 (100,000 iterations)"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_image_aes(image_bytes: bytes, password: str) -> dict:
    """
    AES-256-GCM encryption
    - Unique salt per encryption (never reused)
    - Unique nonce per encryption (never reused)  
    - Authentication tag prevents tampering
    """
    salt = secrets.token_bytes(32)      # 256-bit random salt
    nonce = secrets.token_bytes(12)     # 96-bit random nonce (GCM standard)
    key = derive_key(password, salt)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, image_bytes, None)
    
    # Log encryption event (no sensitive data logged)
    logging.info(f"IMAGE_ENCRYPTED | size={len(image_bytes)} bytes | "
                 f"hash={hashlib.sha256(image_bytes).hexdigest()[:16]}...")
    
    return {
        "ciphertext": ciphertext,
        "salt": salt,
        "nonce": nonce,
        # Package everything together: salt(32) + nonce(12) + ciphertext
        "package": salt + nonce + ciphertext
    }

def decrypt_image_aes(package: bytes, password: str) -> bytes:
    """
    AES-256-GCM decryption
    - Automatically verifies data integrity
    - Raises exception if data was tampered with
    """
    salt = package[:32]
    nonce = package[32:44]
    ciphertext = package[44:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logging.info(f"IMAGE_DECRYPTED | success=True")
        return plaintext
    except Exception:
        logging.warning(f"IMAGE_DECRYPT_FAILED | possible tampering detected!")
        raise ValueError("Decryption failed — wrong password or file was tampered with")

def image_to_sketch(image):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    inv = cv2.bitwise_not(gray)
    blur = cv2.GaussianBlur(inv, (21, 21), 0)
    return cv2.divide(gray, cv2.bitwise_not(blur), scale=256.0)

def verify_token(req):
    token = req.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None
    try:
        return supabase.auth.get_user(token)
    except:
        return None

# ── Security Headers ───────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'"
    return response

# ── Auth Routes ────────────────────────────────────────
@app.route('/api/signup', methods=['POST'])
@limiter.limit("3 per minute")
def signup():
    data = request.json
    email = data.get('email', '')
    password = data.get('password', '')
    
    if len(password) < 8:
        return jsonify({"success": False, 
                       "error": "Password must be at least 8 characters"}), 400
    
    logging.info(f"SIGNUP_ATTEMPT | email={email[:3]}***")
    try:
        supabase.auth.sign_up({"email": email, "password": password})
        logging.info(f"SIGNUP_SUCCESS | email={email[:3]}***")
        return jsonify({"success": True, "message": "Account created!"})
    except Exception as e:
        logging.warning(f"SIGNUP_FAILED | reason={str(e)[:50]}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    email = data.get('email', '')
    password = data.get('password', '')
    
    logging.info(f"LOGIN_ATTEMPT | email={email[:3]}*** | ip={request.remote_addr}")
    try:
        res = supabase.auth.sign_in_with_password({
            "email": email, "password": password
        })
        logging.info(f"LOGIN_SUCCESS | email={email[:3]}***")
        return jsonify({
            "success": True,
            "token": res.session.access_token,
            "email": res.user.email
        })
    except Exception as e:
        logging.warning(f"LOGIN_FAILED | email={email[:3]}*** | ip={request.remote_addr}")
        # Generic error message (don't reveal if email exists)
        return jsonify({"success": False, 
                       "error": "Invalid email or password"}), 401

# ── Image Processing Routes ────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
@limiter.limit("10 per hour")
def encrypt():
    user = verify_token(request)
    if not user:
        logging.warning(f"UNAUTHORIZED_ENCRYPT | ip={request.remote_addr}")
        return jsonify({"error": "Authentication required"}), 401

    file = request.files.get('image')
    password = request.form.get('password', '')

    if not file:
        return jsonify({"error": "No image provided"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
        return jsonify({"error": "Invalid file type"}), 400
    if len(file.read()) > 10 * 1024 * 1024:  # 10MB limit
        return jsonify({"error": "File too large (max 10MB)"}), 400
    
    file.seek(0)
    image_bytes = file.read()
    
    try:
        result = encrypt_image_aes(image_bytes, password)
        # Return encrypted package as downloadable .enc file
        return send_file(
            io.BytesIO(result["package"]),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='encrypted.enc'
        )
    except Exception as e:
        logging.error(f"ENCRYPT_ERROR | {str(e)}")
        return jsonify({"error": "Encryption failed"}), 500

@app.route('/api/decrypt', methods=['POST'])
@limiter.limit("10 per hour")
def decrypt():
    user = verify_token(request)
    if not user:
        logging.warning(f"UNAUTHORIZED_DECRYPT | ip={request.remote_addr}")
        return jsonify({"error": "Authentication required"}), 401

    file = request.files.get('image')
    password = request.form.get('password', '')

    if not file or not password:
        return jsonify({"error": "File and password required"}), 400

    try:
        package = file.read()
        image_bytes = decrypt_image_aes(package, password)
        return send_file(
            io.BytesIO(image_bytes),
            mimetype='image/png',
            as_attachment=True,
            download_name='decrypted.png'
        )
    except ValueError as e:
        logging.warning(f"DECRYPT_FAILED | ip={request.remote_addr} | wrong_key_or_tampered")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.error(f"DECRYPT_ERROR | {str(e)}")
        return jsonify({"error": "Decryption failed"}), 500

@app.route('/api/sketch', methods=['POST'])
@limiter.limit("20 per hour")
def sketch():
    user = verify_token(request)
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    file = request.files.get('image')
    if not file:
        return jsonify({"error": "No image provided"}), 400
    img_array = np.frombuffer(file.read(), np.uint8)
    image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    result = image_to_sketch(image)
    _, buffer = cv2.imencode('.png', result)
    return send_file(io.BytesIO(buffer.tobytes()),
        mimetype='image/png', as_attachment=True,
        download_name='sketch.png')

@app.route('/')
def index():
    return render_template_string(open('index.html', encoding='utf-8').read())

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
