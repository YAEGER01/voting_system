from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase_client import supabase
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
import os
import re
import sys
import platform
import hashlib
import uuid
import requests
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import time
import threading
from flask import jsonify

PH_TZ = timezone(timedelta(hours=8))


def format_ph_time(dt_str):
    if not dt_str:
        return 'Not set'
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        dt = dt.astimezone(PH_TZ)
        return dt.strftime('%B %d, %Y %I:%M%p')
    except Exception:
        return 'Invalid date'


class Block:

    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # e.g., vote info
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True)}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:

    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, str(time.time()), {"genesis": True}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        latest_block = self.get_latest_block()
        new_block = Block(index=latest_block.index + 1,
                          timestamp=str(time.time()),
                          data=data,
                          previous_hash=latest_block.hash)
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True


BLOCKCHAIN_FILE = "blockchain_data.json"
blockchain_lock = threading.Lock()


def save_blockchain_to_file(blockchain):
    with blockchain_lock:
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump([{
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "hash": block.hash
            } for block in blockchain.chain],
                      f,
                      indent=2)


def load_blockchain_from_file():
    if not os.path.exists(BLOCKCHAIN_FILE):
        return None
    with open(BLOCKCHAIN_FILE, "r") as f:
        chain_data = json.load(f)
    chain = []
    for b in chain_data:
        block = Block(index=b["index"],
                      timestamp=b["timestamp"],
                      data=b["data"],
                      previous_hash=b["previous_hash"])
        block.hash = b["hash"]
        chain.append(block)
    bc = Blockchain()
    bc.chain = chain
    return bc


# Initialize blockchain (in-memory)
vote_blockchain = load_blockchain_from_file() or Blockchain()


def add_block_and_save(self, data):
    latest_block = self.get_latest_block()
    new_block = Block(index=latest_block.index + 1,
                      timestamp=str(time.time()),
                      data=data,
                      previous_hash=latest_block.hash)
    self.chain.append(new_block)
    save_blockchain_to_file(self)
    return new_block


Blockchain.add_block = add_block_and_save

AES_KEY = os.getenv("AES_KEY",
                    "thisisaverysecretkey1234567890123456").encode()[:32]


def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + chr(pad_len) * pad_len


def unpad(s):
    pad_len = ord(s[-1])
    return s[:-pad_len]


def encrypt_vote(plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(iv + ct_bytes).decode()


def decrypt_vote(ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt.decode())


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret")

# --- Fla configuration for Gmail SMTP ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vdark699@gmail.com'  # <-- your Gmail address
app.config[
    'MAIL_PASSWORD'] = 'gwgp rxwf jpks bmaz'  # <-- your Gmail app password

mail = Mail(app)

UPLOAD_FOLDER = os.path.join('static', 'uploads', 'school_ids')
CANDIDATE_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'candidates')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

RECAPTCHA_SITE_KEY = "6Lf6ioErAAAAAMgfS8qXBOmQ-lMUJXoHEK544AEe"
RECAPTCHA_SECRET_KEY = "6Lf6ioErAAAAAN9CgpFldNEwhmB3Z-vVyRgNrCLw"


def verify_recaptcha(response_token):
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {'secret': RECAPTCHA_SECRET_KEY, 'response': response_token}
    try:
        r = requests.post(url, data=data, timeout=5)
        result = r.json()
        return result.get("success", False)
    except Exception:
        return False


def generate_otp():
    return '{:06d}'.format(random.randint(0, 999999))


def send_otp_email(to_email, otp):
    # HTML email template
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>UNIVOTE Password Reset</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: #ffffff;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 300;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .otp-container {{
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 30px 0;
            }}
            .otp-code {{
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 8px;
                margin: 10px 0;
                text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            }}
            .warning {{
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
                color: #856404;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px 30px;
                text-align: center;
                border-top: 1px solid #e9ecef;
                font-size: 12px;
                color: #6c757d;
            }}
            .button {{
                display: inline-block;
                padding: 12px 30px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
                transition: transform 0.2s;
            }}
            .button:hover {{
                transform: translateY(-2px);
            }}
            @media (max-width: 600px) {{
                body {{
                    padding: 10px;
                }}
                .content {{
                    padding: 20px 15px;
                }}
                .otp-code {{
                    font-size: 24px;
                    letter-spacing: 4px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🗳️ UNIVOTE</h1>
                <p>Secure Password Reset Request</p>
            </div>

            <div class="content">
                <h2>Hello there! 👋</h2>
                <p>We received a request to reset the password for your UNIVOTE account. To proceed with the password reset, please use the One-Time Password (OTP) below:</p>

                <div class="otp-container">
                    <p style="margin: 0; font-size: 16px;">Your OTP Code:</p>
                    <div class="otp-code">{otp}</div>
                    <p style="margin: 0; font-size: 14px; opacity: 0.9;">⏰ Valid for 10 minutes</p>
                </div>

                <div class="warning">
                    <strong>🔒 Security Notice:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>This OTP is valid for <strong>10 minutes only</strong></li>
                        <li>Never share this code with anyone</li>
                        <li>UNIVOTE staff will never ask for your OTP</li>
                        <li>If you didn't request this reset, please ignore this email</li>
                    </ul>
                </div>

                <p>If you're having trouble with the password reset process, please contact our support team.</p>

            </div>

            <div class="footer">
                <p><strong>UNIVOTE Support Team</strong></p>
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 UNIVOTE. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text fallback for email clients that don't support HTML
    text_body = f"""
UNIVOTE Password Reset Request

Dear User,

We received a request to reset the password for your UNIVOTE account.

Your One-Time Password (OTP) is: {otp}

This OTP is valid for 10 minutes. Please do not share this code with anyone.

SECURITY NOTICE:
- This OTP expires in 10 minutes
- Never share this code with anyone
- UNIVOTE staff will never ask for your OTP
- If you didn't request this reset, please ignore this email

If you need assistance, please contact our support team.

Best regards,
UNIVOTE Support Team

---
This is an automated message. Please do not reply to this email.
© 2024 UNIVOTE. All rights reserved.
"""

    # Create message with both HTML and text versions
    msg = Message(subject='🔐 UNIVOTE Password Reset - OTP Code',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email],
                  body=text_body,
                  html=html_body)

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Gmail SMTP error: {e}")
        return False


def send_registration_email(to_email, first_name):
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Welcome to UNIVOTE</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f4f4f4;
                color: #333;
                padding: 0;
                margin: 0;
            }}
            .container {{
                background: #fff;
                max-width: 600px;
                margin: 40px auto;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(0,0,0,0.08);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #25c18c 0%, #21532a 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .content {{
                padding: 30px 40px;
            }}
            .footer {{
                background: #f8f9fa;
                color: #888;
                text-align: center;
                padding: 18px 40px;
                font-size: 13px;
            }}
            @media (max-width: 600px) {{
                .content, .footer {{ padding: 18px 10px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🗳️ UNIVOTE SYSTEM</h1>
            </div>
            <div class="content">
                <h2>Hello{', ' + first_name if first_name else ''}!</h2>
                <p>
                    Thank you for registering to <strong>UNIVOTE SYSTEM</strong>.<br>
                    Your registration is now under review by our admin team.
                </p>
                <p>
                    <strong>What happens next?</strong><br>
                    We will notify you via this email once your registration is approved or if further information is needed.
                </p>
                <p>
                    If you have any questions, please contact our support team.<br>
                    <br>
                    Best regards,<br>
                    <strong>UNIVOTE Team</strong>
                </p>
            </div>
            <div class="footer">
                This is an automated message. Please do not reply.<br>
                &copy; 2024 UNIVOTE. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """
    text_body = f"""Hello{', ' + first_name if first_name else ''}!

Thank you for registering to UNIVOTE SYSTEM.
Your registration is now under review by our admin team.

What happens next?
We will notify you via this email once your registration is approved or if further information is needed.

If you have any questions, please contact our support team.

Best regards,
UNIVOTE Team

---
This is an automated message. Please do not reply.
© 2024 UNIVOTE. All rights reserved.
"""
    msg = Message(subject="Thank you for registering to UNIVOTE SYSTEM",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email],
                  body=text_body,
                  html=html_body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Registration email error: {e}")
        return False


# --- OTP Password Reset Flow ---


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Please enter your email address.", "danger")
            return redirect(request.url)
        try:
            resp = supabase.table('user').select('*').eq(
                'email', email).single().execute()
            user = resp.data
        except Exception:
            user = None
        if not user:
            flash("No account found with that email.", "danger")
            return redirect(request.url)
        otp = generate_otp()
        expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        supabase.table('user').update({
            'reset_otp': otp,
            'reset_otp_expiry': expiry.isoformat()
        }).eq('id', user['id']).execute()

        # Log the OTP request
        supabase.table('logs').insert({
            'user_id': user['id'],
            'action': 'FORGOT_PASSWORD_REQUEST',
            'table_name': 'user',
            'query_type': 'SYSTEM',
            'target': f"Email: {email}",
            'new_data': f"OTP set with expiry {expiry.isoformat()}",
            'timestamp': datetime.now().isoformat()
        }).execute()

        send_otp_email(email, otp)
        flash("An OTP has been sent to your email.", "info")
        return redirect(url_for('verify_otp', email=email))
    return render_template('forgot_password.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    if not email:
        flash("Missing email.", "danger")
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        resp = supabase.table('user').select('*').eq('email',
                                                     email).single().execute()

        user = resp.data
        if not user or not user.get('reset_otp') or not user.get(
                'reset_otp_expiry'):
            flash("Invalid or expired OTP.", "danger")
            return redirect(url_for('forgot_password'))
        expiry = datetime.fromisoformat(user['reset_otp_expiry'])
        if datetime.now(timezone.utc) > expiry:
            flash("OTP has expired. Please request a new one.", "danger")
            return redirect(url_for('forgot_password'))
        if otp != user['reset_otp']:
            flash("Incorrect OTP. Please try again.", "danger")
            return render_template('verify_otp.html', email=email)

        # Log OTP verification success
        supabase.table('logs').insert({
            'user_id': user['id'],
            'action': 'OTP_VERIFIED',
            'table_name': 'user',
            'query_type': 'SYSTEM',
            'target': f"Email: {email}",
            'new_data': 'OTP matched successfully',
            'timestamp': datetime.now().isoformat()
        }).execute()

        # OTP is correct
        return redirect(url_for('reset_password_otp', email=email))
    return render_template('verify_otp.html', email=email)


@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email')
    if not email:
        flash("Missing email.", "danger")
        return redirect(url_for('forgot_password'))

    resp = supabase.table('user').select('*').eq('email',
                                                 email).single().execute()
    user = resp.data

    if not user:
        flash("No account found with that email.", "danger")
        return redirect(url_for('forgot_password'))

    otp = generate_otp()
    expiry = datetime.now(UTC) + timedelta(minutes=10)

    # ✅ Update reset_otp and expiry
    supabase.table('user').update({
        'reset_otp': otp,
        'reset_otp_expiry': expiry.isoformat()
    }).eq('id', user['id']).execute()

    # Log OTP resend
    supabase.table('logs').insert({
        'user_id': user['id'],
        'action': 'RESEND_OTP',
        'table_name': 'user',
        'query_type': 'SYSTEM',
        'target': f"Email: {email}",
        'new_data': f"OTP resent with new expiry {expiry.isoformat()}",
        'timestamp': datetime.now().isoformat()
    }).execute()

    # ✅ Send the OTP email
    send_otp_email(email, otp)

    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp', email=email))


@app.route('/reset_password_otp', methods=['GET', 'POST'])
def reset_password_otp():
    email = request.args.get('email') or request.form.get('email')
    if not email:
        flash("Missing email.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not password or not confirm:
            flash("Please fill in all fields.", "danger")
            return render_template('reset_password_otp.html', email=email)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('reset_password_otp.html', email=email)
        if len(password) < 8 or not re.match(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$',
                password):
            flash("Password does not meet requirements.", "danger")
            return render_template('reset_password_otp.html', email=email)

        resp = supabase.table('user').select('*').eq('email',
                                                     email).single().execute()
        user = resp.data
        if not user:
            flash("No account found.", "danger")
            return redirect(url_for('forgot_password'))

        # Perform password reset
        update_data = {
            'password_hash': generate_password_hash(password),
            'reset_otp': None,
            'reset_otp_expiry': None
        }
        supabase.table('user').update(update_data).eq('id',
                                                      user['id']).execute()

        # Log password reset
        supabase.table('logs').insert({
            'user_id': user['id'],
            'action': 'PASSWORD_RESET',
            'table_name': 'user',
            'query_type': 'UPDATE',
            'target': f"Email: {email}",
            'new_data': 'Password updated, OTP cleared',
            'timestamp': datetime.now().isoformat()
        }).execute()

        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password_otp.html', email=email)


DEPARTMENT_LOGOS = {
    'CCSICT': 'ccsict.png',
    'CCJE': 'ccje.png',
    'CBM': 'cbm.png',
    'SAS': 'SAS.png',
    'PS': 'PS.png',
    'EDUC': 'educ.png',
    'IAT': 'iat.png',
}

COURSE_FULL_NAMES = {
    "BSIT": "Bachelor of Science in Information Technology",
    "BSIndTech": "Bachelor of Science in Industrial Technology",
    "BSCS": "Bachelor of Science in Computer Science",
    "BSEMC": "Bachelor of Science in Entertainment and Multimedia Computing",
    "BSBA": "Bachelor of Science in Business Administration",
    "BSM": "Bachelor of Science in Management",
    "BSHM": "Bachelor of Science in Hospitality Management",
    "BSTM": "Bachelor of Science in Tourism Management",
    "BSAIS": "Bachelor of Science in Accounting Information System",
    "BSMA": "Bachelor of Science in Management Accounting",
    "BSEntrep": "Bachelor of Science in Entrepreneurship",
    "BSLM": "Bachelor of Science in Legal Management",
    "BSCRIM": "Bachelor of Science in Criminology",
    "BSED": "Bachelor of Secondary Education",
    "BEED": "Bachelor of Elementary Education",
    "BPEd": "Bachelor of Physical Education",
    "BAELS": "Bachelor of Arts in English Language Studies",
    "BAPS": "Bachelor of Arts in Political Science",
    "DAS": "Diploma in Agricultural Sciences"
}


def allowed_file(filename):
    return '.' in filename and filename.rsplit(
        '.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.template_filter('nl2br')
def nl2br_filter(s):
    return s.replace('\n', '<br>') if s else ''


@app.route('/')
def index():
    return render_template('UNIVOTE.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash("Please complete the reCAPTCHA.", "danger")
            return redirect(request.url)

        school_id = request.form.get('school_id', '').strip()
        password = request.form.get('password', '')

        if not school_id or not password:
            flash("Please fill in all fields.", 'danger')
        else:
            try:
                resp = supabase.table('user').select('*').eq(
                    'school_id', school_id).single().execute()
                user = resp.data
            except Exception:
                user = None

            if not user:
                pending_check = supabase.table('pending_users').select(
                    'id').eq('school_id', school_id).execute()
                if pending_check.data:
                    flash(
                        "YOUR REGISTRATION IS UNDER REVIEW. PLEASE WAIT FOR ADMIN APPROVAL.",
                        'warning')
                else:
                    flash("Invalid School ID or Password.", 'danger')
                return redirect(request.url)

            if check_password_hash(user['password_hash'], password):
                session['school_id'] = user['school_id']
                session['role'] = user['role']
                session['user_id'] = user['id']  # Store numeric user ID

                # Update active status
                supabase.table('user').update({
                    'active': 'ACTIVE'
                }).eq('school_id', school_id).execute()

                # Log the login action
                supabase.table('logs').insert({
                    'user_id':
                    user['id'],
                    'action':
                    'LOGIN_SUCCESS',
                    'table_name':
                    'user',
                    'query_type':
                    'SYSTEM',
                    'target':
                    f'Login from IP {request.remote_addr} with role {user["role"]}',
                    'new_data':
                    'active=ACTIVE',
                    'timestamp':
                    datetime.now().isoformat()
                }).execute()

                # Redirect based on role
                if user['role'] == 'admin':
                    return render_template(
                        'redirecting.html',
                        target=url_for('admin_dashboard'),
                        message="REDIRECTING to ADMIN DASHBOARD...")
                elif user['role'] == 'SysAdmin':
                    return render_template(
                        'redirecting.html',
                        target=url_for('system_admin'),
                        message="REDIRECTING to SYSTEM ADMIN DASHBOARD...")
                else:
                    return render_template(
                        'redirecting.html',
                        target=url_for('dashboard'),
                        message="REDIRECTING to DASHBOARD...")
            else:
                flash("Invalid School ID or Password.", 'danger')

    return render_template('login.html', recaptcha_site_key=RECAPTCHA_SITE_KEY)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find user by token and check expiry
    resp = supabase.table('user').select('*').eq('reset_token',
                                                 token).single().execute()
    user = resp.data
    if not user or not user.get('reset_token_expiry'):
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for('login'))

    expiry = datetime.fromisoformat(user['reset_token_expiry'])
    if datetime.utcnow() > expiry:
        flash("Reset link has expired.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not password or not confirm:
            flash("Please fill in all fields.", "danger")
            return redirect(request.url)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(request.url)

        # Update password and clear token
        supabase.table('user').update({
            'password_hash':
            generate_password_hash(password),
            'reset_token':
            None,
            'reset_token_expiry':
            None
        }).eq('id', user['id']).execute()

        # Log token-based password reset
        supabase.table('logs').insert({
            'user_id': user['id'],
            'action': 'PASSWORD_RESET_LINK',
            'table_name': 'user',
            'query_type': 'UPDATE',
            'target': f"Email: {user['email']}",
            'new_data': 'Password updated, reset token cleared',
            'timestamp': datetime.now().isoformat()
        }).execute()

        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        school_id = request.form.get('school-id', '').strip()
        department = request.form.get('department', '').strip()
        course_code = request.form.get('course', '').strip()
        track = request.form.get('track', '').strip()
        year_level = request.form.get('year_level', '').strip()
        course = COURSE_FULL_NAMES.get(course_code, course_code)
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        first_name = request.form.get('first-name', '').strip()
        last_name = request.form.get('last-name', '').strip()
        phone = request.form.get('phone', '').strip()
        front_file = request.files.get('school-id-front')
        back_file = request.files.get('school-id-back')

        if not all([
                school_id, department, course_code, email, password,
                confirm_password, first_name, last_name, phone, front_file,
                back_file, year_level
        ]):
            flash("All fields are required.", 'danger')
            return redirect(request.url)

        if not allowed_file(front_file.filename) or not allowed_file(
                back_file.filename):
            flash('Only image files are allowed for ID photos.', 'danger')
            return redirect(request.url)

        if len(front_file.read()) > MAX_FILE_SIZE or len(
                back_file.read()) > MAX_FILE_SIZE:
            flash('Each ID image must be less than 5MB.', 'danger')
            return redirect(request.url)
        front_file.seek(0)
        back_file.seek(0)

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(request.url)

        if not re.match(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$',
                password):
            flash(
                'Password must have uppercase, lowercase, digit, and special character.',
                'danger')
            return redirect(request.url)

        for field, value in [('school_id', school_id), ('email', email),
                             ('phone', phone)]:
            resp = supabase.table('user').select('id').eq(field,
                                                          value).execute()
            if resp.data:
                flash(f'{field.replace("_", " ").title()} already registered.',
                      'danger')
                return redirect(request.url)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        front_filename = secure_filename(
            f"{school_id}_front_{front_file.filename}")
        back_filename = secure_filename(
            f"{school_id}_back_{back_file.filename}")
        front_path = os.path.join(UPLOAD_FOLDER, front_filename)
        back_path = os.path.join(UPLOAD_FOLDER, back_filename)
        front_file.save(front_path)
        back_file.save(back_path)

        supabase.table('pending_users').insert({
            'school_id': school_id,
            'department': department,
            'course': course,
            'course_code': course_code,
            'track': track,
            'year_level': year_level,
            'email': email,
            'password_plain': password,
            'first_name': first_name,
            'last_name': last_name,
            'phone': phone,
            'id_photo_front': front_path,
            'id_photo_back': back_path
        }).execute()

        supabase.table('logs').insert({
            'user_id': None,
            'action': 'REGISTRATION_REQUEST',
            'table_name': 'pending_users',
            'query_type': 'INSERT',
            'target': f"School ID: {school_id}, Email: {email}",
            'new_data': 'Registration submitted for approval',
            'timestamp': datetime.now().isoformat()
        }).execute()

        # Send registration confirmation email
        send_registration_email(email, first_name)

        flash(
            "Successfully Registered. Please wait for an Admin Approval. We will notify you on your connected email that you've registered.",
            "success")
        return redirect(url_for('register'))

    return render_template('register.html')


def send_approval_email(to_email, first_name):
    html_body = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>UNIVOTE Registration Approved</title>
    </head>
    <body style="font-family: Arial, sans-serif; background: #f4f4f4;">
        <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.08);overflow:hidden;">
            <div style="background:linear-gradient(135deg,#25c18c 0%,#21532a 100%);color:#fff;padding:30px;text-align:center;">
                <h1>🗳️ UNIVOTE SYSTEM</h1>
            </div>
            <div style="padding:30px 40px;">
                <h2>Hello{', ' + first_name if first_name else ''}!</h2>
                <p>
                    Congratulations! Your registration to <strong>UNIVOTE SYSTEM</strong> has been <b>approved</b>.<br>
                    You can now log in and participate in the voting process.
                </p>
                <p>
                    If you have any questions, please contact our support team.<br><br>
                    Best regards,<br>
                    <strong>UNIVOTE Team</strong>
                </p>
            </div>
            <div style="background:#f8f9fa;color:#888;text-align:center;padding:18px 40px;font-size:13px;">
                This is an automated message. Please do not reply.<br>
                &copy; 2024 UNIVOTE. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """
    text_body = f"""Hello{', ' + first_name if first_name else ''}!

Congratulations! Your registration to UNIVOTE SYSTEM has been approved.
You can now log in and participate in the voting process.

If you have any questions, please contact our support team.

Best regards,
UNIVOTE Team

---
This is an automated message. Please do not reply.
© 2024 UNIVOTE. All rights reserved.
"""
    msg = Message(subject="Your UNIVOTE Registration is Approved",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email],
                  body=text_body,
                  html=html_body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Approval email error: {e}")
        return False


def send_rejection_email(to_email, first_name):
    html_body = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>UNIVOTE Registration Update</title>
    </head>
    <body style="font-family: Arial, sans-serif; background: #f4f4f4;">
        <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.08);overflow:hidden;">
            <div style="background:linear-gradient(135deg,#e74c3c 0%,#c0392b 100%);color:#fff;padding:30px;text-align:center;">
                <h1>🗳️ UNIVOTE SYSTEM</h1>
            </div>
            <div style="padding:30px 40px;">
                <h2>Hello{', ' + first_name if first_name else ''}!</h2>
                <p>
                    We regret to inform you that your registration to <strong>UNIVOTE SYSTEM</strong> has been <b>rejected</b>.<br>
                    If you believe this was a mistake or need further assistance, please contact our support team.
                </p>
                <p>
                    Best regards,<br>
                    <strong>UNIVOTE Team</strong>
                </p>
            </div>
            <div style="background:#f8f9fa;color:#888;text-align:center;padding:18px 40px;font-size:13px;">
                This is an automated message. Please do not reply.<br>
                &copy; 2024 UNIVOTE. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """
    text_body = f"""Hello{', ' + first_name if first_name else ''}!

We regret to inform you that your registration to UNIVOTE SYSTEM has been rejected.
If you believe this was a mistake or need further assistance, please contact our support team.

Best regards,
UNIVOTE Team

---
This is an automated message. Please do not reply.
© 2024 UNIVOTE. All rights reserved.
"""
    msg = Message(subject="Your UNIVOTE Registration Update",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email],
                  body=text_body,
                  html=html_body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Rejection email error: {e}")
        return False


@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        school_id = request.form.get('school_id', '').strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        course = request.form.get('course', '').strip()

        if not all([school_id, password, first_name, last_name, course]):
            flash("Please fill in all required fields.", 'danger')
            return redirect(url_for('register_admin'))

        email = f"{school_id}@admin.local"

        resp = supabase.table('user').select('id').or_(
            f'school_id.eq.{school_id},email.eq.{email}').execute()
        if resp.data:
            flash("School ID or generated email already exists.", 'danger')
            return redirect(url_for('register_admin'))

        password_hash = generate_password_hash(password)

        short_uuid = str(uuid.uuid4())[:6]  # Shorter to ensure under 20 chars
        fake_phone = f"adm-{short_uuid}"  # Shortened prefix

        supabase.table('user').insert({
            'school_id': school_id,
            'course': course,
            'department': course,
            'email': email,
            'password_hash': password_hash,
            'first_name': first_name,
            'last_name': last_name,
            'role': 'admin',
            'phone': fake_phone,  # ✅ Now guaranteed < 20 characters
            'id_photo_front': 'N/A',
            'id_photo_back': 'N/A'
        }).execute()

        supabase.table('logs').insert({
            'user_id': None,
            'action': 'ADMIN_REGISTRATION',
            'table_name': 'user',
            'query_type': 'INSERT',
            'target': f"Admin School ID: {school_id}",
            'new_data': f"Email: {email}, Role: admin",
            'timestamp': datetime.now().isoformat()
        }).execute()

        flash("Admin registered successfully!", "success")
        return redirect(url_for('register_admin'))

    return render_template('system_admin.html')


@app.route('/logout')
def logout():
    school_id = session.get('school_id')

    if school_id:
        # Set user as OFFLINE in database
        supabase.table('user').update({
            'active': 'OFFLINE'
        }).eq('school_id', school_id).execute()

        # Fetch user ID for logging
        resp = supabase.table('user').select('id').eq(
            'school_id', school_id).single().execute()
        user = resp.data

        if user:
            supabase.table('logs').insert({
                'user_id':
                user['id'],
                'action':
                'LOGOUT',
                'target':
                f'Logout from IP {request.remote_addr}',
                'table_name':
                'user',
                'query_type':
                'UPDATE',
                'new_data':
                'active=OFFLINE',
                'timestamp':
                datetime.now().isoformat()
            }).execute()

    session.clear()
    return redirect(url_for('login'))


@app.route('/system_admin')
def system_admin():
    if session.get('role') != 'SysAdmin':
        return redirect(url_for('login'))

    # Fetch the latest filing period for 'ALL' department
    settings_resp = supabase.table('settings').select('filing_start', 'filing_end') \
        .eq('department', 'ALL').order('id', desc=True).limit(1).execute()
    settings_row = settings_resp.data[0] if settings_resp.data else None

    filing_start = settings_row['filing_start'] if settings_row else ''
    filing_end = settings_row['filing_end'] if settings_row else ''

    def safe_format(dt_str):
        if not dt_str:
            return 'Not set'
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            dt = dt.astimezone(PH_TZ)
            return dt.strftime('%B %d, %Y %I:%M%p')
        except Exception:
            return 'Invalid date'

    filing_start_display = safe_format(filing_start)
    filing_end_display = safe_format(filing_end)

    # Only allow setting if no period set (not if expired)
    can_set = not filing_start or not filing_end

    return render_template("system_admin.html",
                           filing_start=filing_start,
                           filing_end=filing_end,
                           filing_start_display=filing_start_display,
                           filing_end_display=filing_end_display,
                           can_set=can_set)


@app.route('/voting_admin')
def voting_admin():
    if session.get('role') != 'SysAdmin':
        return redirect(url_for('login'))

    # Fetch VOTING period using correct columns: start_time, end_time
    settings_resp = supabase.table('settings').select('start_time', 'end_time') \
        .eq('department', 'ALL').order('id', desc=True).limit(1).execute()
    settings_row = settings_resp.data[0] if settings_resp.data else None

    voting_start = settings_row['start_time'] if settings_row else ''
    voting_end = settings_row['end_time'] if settings_row else ''

    def safe_format(dt_str):
        if not dt_str:
            return 'Not set'
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            dt = dt.astimezone(PH_TZ)
            return dt.strftime('%B %d, %Y %I:%M%p')
        except Exception:
            return 'Invalid date'

    voting_start_display = safe_format(voting_start)
    voting_end_display = safe_format(voting_end)

    # Allow setting if not set or already expired
    now_utc = datetime.now(timezone.utc)
    can_set = False
    if not voting_start or not voting_end:
        can_set = True
    else:
        try:
            voting_end_dt = datetime.fromisoformat(
                voting_end.replace('Z', '+00:00'))
            if now_utc > voting_end_dt.astimezone(timezone.utc):
                can_set = True
        except Exception:
            can_set = False

    return render_template("system_voting_admin.html",
                           voting_start=voting_start,
                           voting_end=voting_end,
                           voting_start_display=voting_start_display,
                           voting_end_display=voting_end_display,
                           can_set=can_set)


@app.route('/get_data_logs')
def get_data_logs():
    if session.get("role") != "SysAdmin":
        return jsonify([])

    logs_data = supabase.table("logs").select("*").order(
        "timestamp", desc=True).execute().data
    users_data = supabase.table("user").select(
        "id, school_id, first_name, last_name, department, course, track, year_level"
    ).execute().data

    user_map = {u["id"]: u for u in users_data}
    for log in logs_data:
        user = user_map.get(log["user_id"], {})
        log.update({
            "school_id": user.get("school_id", "N/A"),
            "first_name": user.get("first_name", "N/A"),
            "last_name": user.get("last_name", "N/A"),
            "department": user.get("department", "N/A"),
            "course": user.get("course", "N/A"),
            "track": user.get("track", "N/A"),
            "year_level": user.get("year_level", "N/A"),
        })

    return jsonify(logs_data)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'school_id' not in session:
        return redirect(url_for('login'))

    school_id = session['school_id']
    user_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    user = user_resp.data
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    dept_logo = DEPARTMENT_LOGOS.get(user.get('department', '').upper())
    now = datetime.now(timezone.utc)

    department = user.get('department', user.get('course', ''))
    setting_resp = supabase.table('settings').select('*').eq(
        'department', department).order('id', desc=True).limit(1).execute()

    voting_start = None
    voting_end = None
    voting_open = False
    voting_closed = False
    voting_start_display = "Not set"
    voting_end_display = "Not set"

    if setting_resp.data:
        setting = setting_resp.data[0]
        try:
            start_str = setting.get('start_time')
            end_str = setting.get('end_time')

            if start_str and end_str:
                voting_start = datetime.fromisoformat(start_str)
                voting_end = datetime.fromisoformat(end_str)

                if voting_start.tzinfo is None:
                    voting_start = voting_start.replace(tzinfo=timezone.utc)
                if voting_end.tzinfo is None:
                    voting_end = voting_end.replace(tzinfo=timezone.utc)

                voting_start_display = voting_start.astimezone(PH_TZ).strftime(
                    "%B %d, %Y %I:%M %p PH Time")
                voting_end_display = voting_end.astimezone(PH_TZ).strftime(
                    "%B %d, %Y %I:%M %p PH Time")

                voting_open = voting_start <= now <= voting_end
                voting_closed = now > voting_end
        except Exception:
            pass

    if request.method == 'POST':
        if not voting_open:
            flash("Voting is not open at this time.", "danger")
            return redirect(url_for('dashboard'))

        for position_id, candidate_id in request.form.items():
            if position_id.isdigit() and candidate_id.isdigit():
                position_id_int = int(position_id)
                candidate_id_int = int(candidate_id)

                vote_resp = supabase.table('votes').select('*').eq(
                    'student_id', school_id).eq('position_id',
                                                position_id_int).execute()
                if not vote_resp.data:
                    encrypted_candidate_id = encrypt_vote(
                        str(candidate_id_int))

                    supabase.table('votes').insert({
                        'student_id': school_id,
                        'position_id': position_id_int,
                        'candidate_id': encrypted_candidate_id,
                        'candidate_ref': candidate_id_int,
                        'department': department
                    }).execute()

                    supabase.table('logs').insert({
                        'user_id':
                        user['id'],
                        'action':
                        'CAST_VOTE',
                        'table_name':
                        'votes',
                        'query_type':
                        'INSERT',
                        'target':
                        f"Position ID: {position_id_int}",
                        'new_data':
                        f"Encrypted Candidate ID: {encrypted_candidate_id}",
                        'timestamp':
                        datetime.now().isoformat()
                    }).execute()

                    hashed_student_id = hashlib.sha256(
                        school_id.encode()).hexdigest()
                    vote_blockchain.add_block({
                        "student_id": hashed_student_id,
                        "position_id": position_id_int,
                        "candidate_id": encrypted_candidate_id,
                        "timestamp": str(time.time())
                    })

        flash('Your vote has been submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    positions_resp = supabase.table('positions').select('*').eq(
        'department', department).execute()
    positions = positions_resp.data if positions_resp.data else []

    candidates_per_position = {}
    votable_positions = []
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates = cands_resp.data if cands_resp.data else []
        candidates_per_position[pos['id']] = candidates
        if candidates:
            votable_positions.append(pos)

    voted_positions_resp = supabase.table('votes').select('position_id').eq(
        'student_id', school_id).execute()
    voted_positions = [v['position_id'] for v in voted_positions_resp.data
                       ] if voted_positions_resp.data else []
    all_voted = all(pos['id'] in voted_positions for pos in votable_positions)

    voting_not_started = voting_start and now < voting_start

    return render_template('dashboard.html',
                           user=user,
                           dept_logo=dept_logo,
                           voting_deadline=voting_end,
                           voting_start=voting_start,
                           voting_end=voting_end,
                           voting_start_display=voting_start_display,
                           voting_end_display=voting_end_display,
                           now=now,
                           voting_closed=voting_closed,
                           positions=positions,
                           voted_positions=voted_positions,
                           candidates_per_position=candidates_per_position,
                           all_voted=all_voted,
                           voting_not_started=voting_not_started)


@app.route('/blockchain')
def view_blockchain():
    chain_data = []
    for block in vote_blockchain.chain:
        chain_data.append({
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash
        })
    return Response(json.dumps(chain_data, indent=2),
                    mimetype="application/json")


@app.route('/blockchain_html')
def blockchain_html():
    chain_data = []
    for block in vote_blockchain.chain:
        chain_data.append({
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash
        })
    return render_template('blockchain.html', chain=chain_data)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']

    # Get admin info
    admin_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    admin = admin_resp.data
    department = admin['department']

    # Get active users in same department
    active_users_resp = supabase.table('user').select('*')\
        .eq('active', 'ACTIVE').eq('department', department).execute()
    active_users = active_users_resp.data

    supabase.table('logs').insert({
        'user_id': admin['id'],
        'action': 'VIEW_ADMIN_DASHBOARD',
        'table_name': 'user',
        'query_type': 'READ',
        'target': f"Department: {department}",
        'new_data': f"Fetched {len(active_users)} active users",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return render_template('admin_dash.html',
                           admin=admin,
                           active_users=active_users)


@app.route('/fetch_candidates')
def fetch_candidates():
    if 'school_id' not in session or session.get('role') not in [
            'admin', 'SysAdmin'
    ]:
        return jsonify({'error': 'unauthorized'}), 403

    role = session['role']
    school_id = session['school_id']
    user = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute().data

    if role == 'admin':
        department = user.get('department', user.get('course', ''))
        positions = supabase.table('positions').select('*').eq(
            'department', department).order('name').execute().data or []
    else:  # SysAdmin: unrestricted
        positions = supabase.table('positions').select('*').order(
            'name').execute().data or []

    result = []
    for pos in positions:
        cands = supabase.table('candidates').select('id, name').eq(
            'position_id', pos['id']).execute().data or []
        for cand in cands:
            cid = cand['id']
            votes = supabase.table('votes').select('id') \
                .eq('candidate_ref', int(cid)).execute().data
            cand['vote_count'] = len(votes)
        result.append({'position': pos, 'candidates': cands})

    # Insert log here
    supabase.table('logs').insert({
        'user_id': user['id'],
        'action': 'FETCH_CANDIDATES',
        'table_name': 'candidates',
        'query_type': 'READ',
        'target': f"Role: {role}",
        'new_data': f"{len(positions)} positions fetched",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return jsonify(result)


@app.route('/vote_breakdown/<candidate_id>')
def vote_breakdown(candidate_id):
    if 'school_id' not in session or session.get('role') not in [
            'admin', 'SysAdmin'
    ]:
        return jsonify({'error': 'unauthorized'}), 403

    role = session['role']
    school_id = session['school_id']
    user = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute().data
    department = user.get('department', user.get('course', ''))

    vote_records = supabase.table('votes') \
        .select('student_id') \
        .eq('candidate_ref', int(candidate_id)) \
        .execute().data

    student_ids = [
        v['student_id'] for v in vote_records if v.get('student_id')
    ]
    if not student_ids:
        return jsonify([])

    users = supabase.table('user') \
        .select('year_level, department, course, track, school_id') \
        .in_('school_id', student_ids) \
        .execute().data

    breakdown = {}
    total = 0

    for u in users:
        if role == 'admin' and u.get('department') != department:
            continue  # filter out votes outside admin’s department

        y = u['year_level']
        d = u['department']
        c = u['course']
        t = u['track']
        if not all([y, d, c, t]):
            continue
        breakdown.setdefault(y, {}).setdefault(d, {}).setdefault(
            c, {}).setdefault(t, 0)
        breakdown[y][d][c][t] += 1
        total += 1

    supabase.table('logs').insert({
        'user_id': user['id'],
        'action': 'VIEW_VOTE_BREAKDOWN',
        'table_name': 'votes',
        'query_type': 'READ',
        'target': f"Candidate ID: {candidate_id}",
        'new_data': f"{total} votes analyzed",
        'timestamp': datetime.now().isoformat()
    }).execute()
    return jsonify({'nested': breakdown, 'total_votes': total})


from flask import make_response
from datetime import datetime
import csv
import io


@app.route('/vote_breakdown_export/<format>')
def vote_breakdown_export(format):
    if 'school_id' not in session or session.get('role') not in [
            'admin', 'SysAdmin'
    ]:
        return "Unauthorized", 403

    school_id = session['school_id']
    role = session['role']
    user_data = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute().data
    department = user_data.get('department') or user_data.get('course', '')

    if role == 'admin':
        positions = supabase.table('positions').select('*').eq(
            'department', department).order('name').execute().data or []
    else:
        positions = supabase.table('positions').select('*').order(
            'name').execute().data or []

    result = []

    for pos in positions:
        candidates = supabase.table('candidates').select('id, name').eq(
            'position_id', pos['id']).execute().data or []
        for cand in candidates:
            votes = supabase.table('votes').select('student_id').eq(
                'candidate_ref', cand['id']).execute().data or []
            student_ids = [
                v['student_id'] for v in votes if v.get('student_id')
            ]
            breakdown = {}
            vote_count = 0

            if student_ids:
                user_infos = supabase.table('user').select('year_level, department, course, track') \
                    .in_('school_id', student_ids).execute().data or []

                for u in user_infos:
                    if role == 'admin' and u.get('department') != department:
                        continue
                    y, d, c, t = u.get('year_level'), u.get(
                        'department'), u.get('course'), u.get('track')
                    if not all([y, d, c, t]):
                        continue
                    breakdown.setdefault(y, {}).setdefault(d, {}).setdefault(
                        c, {}).setdefault(t, 0)
                    breakdown[y][d][c][t] += 1
                    vote_count += 1

            result.append({
                'position': pos['name'],
                'candidate': cand['name'],
                'vote_count': vote_count,
                'breakdown': breakdown
            })

    year = datetime.now().year
    filename = f"vote_breakdown_{year}.{format}"

    if format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Official Voting Results', f"Year: {year}"])
        writer.writerow([])
        writer.writerow([
            'Position', 'Candidate', 'Total Votes', 'Breakdown Path', 'Votes'
        ])

        for r in result:
            writer.writerow(
                [r['position'], r['candidate'], r['vote_count'], '', ''])
            for y in r['breakdown']:
                for d in r['breakdown'][y]:
                    for c in r['breakdown'][y][d]:
                        for t in r['breakdown'][y][d][c]:
                            count = r['breakdown'][y][d][c][t]
                            path = f"{y} > {d} > {c} > {t}"
                            writer.writerow(['', '', '', path, count])
            writer.writerow([])

        response = make_response(output.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/csv"
        return response

    elif format == 'txt':
        output = io.StringIO()
        output.write(f"OFFICIAL VOTING RESULTS\nYear: {year}\n\n")
        for r in result:
            output.write(f"Position: {r['position']}\n")
            output.write(f"  Candidate: {r['candidate']}\n")
            output.write(f"  Total Votes: {r['vote_count']}\n")
            for y in r['breakdown']:
                for d in r['breakdown'][y]:
                    for c in r['breakdown'][y][d]:
                        for t in r['breakdown'][y][d][c]:
                            count = r['breakdown'][y][d][c][t]
                            output.write(
                                f"    {y} > {d} > {c} > {t}: {count}\n")
            output.write("-" * 40 + "\n")

        response = make_response(output.getvalue())
        response.headers[
            "Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/plain"
        return response

    return "Unsupported format", 400


@app.route('/vote_tally')
def vote_tally():
    if 'school_id' not in session or session.get('role') != 'SysAdmin':
        flash("You must be an admin to view the vote tally.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    admin = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute().data
    department = admin.get('department', admin.get('course', ''))

    positions_resp = supabase.table('positions').select('*').eq(
        'department', department).execute()
    positions = positions_resp.data or []

    # Final data container per position
    tally_by_position = []

    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates = cands_resp.data or []

        position_table = []

        for cand in candidates:
            # Get all votes for this candidate
            # Get all votes under this position
            votes_resp = supabase.table('votes').select('*').eq(
                'position_id', pos['id']).execute()
            votes = votes_resp.data or []

            # Now filter only those votes that match the current candidate after decrypting
            relevant_votes = []
            for v in votes:
                try:
                    decrypted_cid = int(decrypt_vote(v['candidate_id']))
                    if decrypted_cid == cand['id']:
                        relevant_votes.append(v)
                except:
                    continue
            votes = votes_resp.data or []

            # Breakdown holder: {(year, course, track): count}
            breakdown = {}

            for v in relevant_votes:
                student_id = v.get('student_id')
                if not student_id:
                    continue
                user_resp = supabase.table('user').select(
                    'year_level', 'course', 'track',
                    'department').eq('school_id',
                                     student_id).single().execute()
                user = user_resp.data
                if not user or user.get('department') != department:
                    continue

                key = (user.get('year_level',
                                'N/A'), user.get('course', 'N/A'),
                       user.get('track', 'N/A'))
                breakdown[key] = breakdown.get(key, 0) + 1

            # Add all rows from breakdown
            for (year, course, track), count in breakdown.items():
                position_table.append({
                    'candidate': cand['name'],
                    'year': year,
                    'course': course,
                    'track': track,
                    'votes': count
                })

            # ✅ Ensure at least one row if candidate has no votes
            if not breakdown:
                position_table.append({
                    'candidate': cand['name'],
                    'year': '—',
                    'course': '—',
                    'track': '—',
                    'votes': 0
                })

        tally_by_position.append({
            'position': pos['name'],
            'rows': position_table
        })

    # ... after tally_by_position is built

    supabase.table('logs').insert({
        'user_id': admin['id'],
        'action': 'VIEW_VOTE_TALLY',
        'table_name': 'votes',
        'query_type': 'READ',
        'target': f"Department: {department}",
        'new_data': f"Tally generated for {len(tally_by_position)} positions",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return render_template('vote_tally.html',
                           tally_by_position=tally_by_position)


from datetime import datetime, timedelta, timezone as dt_timezone
from pytz import timezone as pytz_timezone

PH_TZ = pytz_timezone('Asia/Manila')


@app.route('/vote_results_report')
def vote_results_report():
    if 'school_id' not in session or session.get('role') not in [
            'admin', 'SysAdmin'
    ]:
        return "Unauthorized", 403

    school_id = session['school_id']
    role = session['role']

    user = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute().data
    department = user.get('department', user.get('course', ''))

    # Retrieve voting end_time from settings
    settings_query = supabase.table('settings').select('end_time')
    settings = (settings_query.eq('department',
                                  department).single().execute().data
                if role == 'admin' else settings_query.single().execute().data)

    if not settings or not settings.get('end_time'):
        return "Voting schedule not configured.", 400

    try:
        # Convert ISO to PH time
        end_time_utc = datetime.fromisoformat(settings['end_time'].replace(
            'Z', '+00:00'))
        end_time_ph = end_time_utc.astimezone(PH_TZ)
    except Exception:
        return "Invalid end time format.", 500

    now_ph = datetime.now(PH_TZ)
    view_start = end_time_ph + timedelta(minutes=2)
    view_end = view_start + timedelta(minutes=10)

    if now_ph < view_start or now_ph > view_end:
        return render_template('vote_results_unavailable.html',
                               view_start=view_start,
                               view_end=view_end)

    if role == 'admin':
        positions = supabase.table('positions').select('*') \
            .eq('department', department).order('name').execute().data or []
    else:
        positions = supabase.table('positions').select('*') \
            .order('name').execute().data or []

    report_data = []

    for pos in positions:
        candidates = supabase.table('candidates').select('id, name') \
            .eq('position_id', pos['id']).execute().data or []

        candidate_rows = []
        for cand in candidates:
            votes = supabase.table('votes').select('student_id') \
                .eq('candidate_ref', int(cand['id'])).execute().data or []

            student_ids = [
                v['student_id'] for v in votes if v.get('student_id')
            ]
            vote_count = len(student_ids)

            breakdown = {}
            if student_ids:
                users = supabase.table('user').select('year_level, department, course, track') \
                    .in_('school_id', student_ids).execute().data or []

                for u in users:
                    if role == 'admin' and u.get('department') != department:
                        continue
                    y, d, c, t = u.get('year_level'), u.get(
                        'department'), u.get('course'), u.get('track')
                    if not all([y, d, c, t]):
                        continue
                    breakdown.setdefault(y, {}).setdefault(d, {}).setdefault(
                        c, {}).setdefault(t, 0)
                    breakdown[y][d][c][t] += 1

            candidate_rows.append({
                'name': cand['name'],
                'vote_count': vote_count,
                'breakdown': breakdown
            })

        report_data.append({
            'position': pos['name'],
            'candidates': candidate_rows
        })

    priority_order = [
        "President", "Vice President", "Secretary", "Treasurer", "Auditor",
        "PRO", "Senator", "Representative"
    ]

    def get_priority(pos_name):
        return priority_order.index(
            pos_name) if pos_name in priority_order else len(priority_order)

    report_data.sort(key=lambda block: get_priority(block['position']))
    current_year = datetime.now(PH_TZ).year

    return render_template('vote_results_report.html',
                           current_year=current_year,
                           report_data=report_data)


@app.route('/candidates')
def candidates():
    if 'school_id' not in session:
        flash("You must be logged in to view candidates.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    user_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    user = user_resp.data
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    department = user.get('department', user.get('course', ''))
    positions_resp = supabase.table('positions').select('*').eq(
        'department', department).order('name', desc=False).execute()
    positions = positions_resp.data if positions_resp.data else []

    positions_with_candidates = []
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates = cands_resp.data if cands_resp.data else []
        positions_with_candidates.append({
            'position': pos,
            'candidates': candidates
        })

    supabase.table('logs').insert({
        'user_id': user['id'],
        'action': 'VIEW_CANDIDATES',
        'table_name': 'candidates',
        'query_type': 'READ',
        'target': f"Department: {department}",
        'new_data': f"{len(positions_with_candidates)} positions accessed",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return render_template('candidates.html',
                           department=department,
                           positions_with_candidates=positions_with_candidates)


@app.route('/contacts')
def contacts():
    return render_template('contacts.html')


@app.route('/candidate/<int:id>')
def candidate_details(id):
    if 'school_id' not in session:
        flash("You must be logged in to view candidate details.", "danger")
        return redirect(url_for('login'))

    cand_resp = supabase.table('candidates').select('*').eq(
        'id', id).single().execute()
    candidate = cand_resp.data
    if not candidate:
        flash("Candidate not found.", "danger")
        return redirect(url_for('candidates'))

    pos_resp = supabase.table('positions').select('name').eq(
        'id', candidate['position_id']).single().execute()
    position_name = pos_resp.data['name'] if pos_resp.data else ''

    # Log candidate detail view
    user_resp = supabase.table('user').select('id').eq(
        'school_id', session['school_id']).single().execute()
    if user_resp.data:
        supabase.table('logs').insert({
            'user_id': user_resp.data['id'],
            'action': 'VIEW_CANDIDATE_DETAILS',
            'table_name': 'candidates',
            'query_type': 'READ',
            'target': f"Candidate ID: {id}, Position: {position_name}",
            'new_data': 'N/A',
            'timestamp': datetime.now().isoformat()
        }).execute()
    return render_template('candidate_details.html',
                           candidate=candidate,
                           position_name=position_name)


@app.route('/view_results')
def view_results():
    if 'school_id' not in session:
        flash("You must be logged in to view results.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    user_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    user = user_resp.data
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    department = user.get('department', user.get('course', ''))
    positions_resp = supabase.table('positions').select('*') \
        .eq('department', department) \
        .order('name', desc=False) \
        .execute()
    positions = positions_resp.data if positions_resp.data else []

    results = []
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates = cands_resp.data if cands_resp.data else []
        candidate_list = []
        # Fetch all votes for this position
        all_votes_resp = supabase.table('votes').select(
            'candidate_id', 'position_id').eq('position_id',
                                              pos['id']).execute()
        all_votes = all_votes_resp.data if all_votes_resp.data else []
        for cand in candidates:
            vote_count = 0
            for v in all_votes:
                try:
                    decrypted_cid = int(decrypt_vote(v['candidate_id']))
                    if decrypted_cid == cand['id']:
                        vote_count += 1
                except Exception:
                    continue
            candidate_list.append({
                'id': cand['id'],
                'name': cand['name'],
                'image': cand['image'],
                'vote_count': vote_count
            })
        # Sort candidates by vote_count descending (leading candidate first)
        candidate_list.sort(key=lambda x: x['vote_count'], reverse=True)
        results.append({'position': pos, 'candidates': candidate_list})

    # Log view results access
    if user_resp.data:
        supabase.table('logs').insert({
            'user_id': user_resp.data['id'],
            'action': 'VIEW_ELECTION_RESULTS',
            'table_name': 'votes',
            'query_type': 'READ',
            'target': f"Department: {department}",
            'new_data': 'Decrypted and tallied vote counts per position',
            'timestamp': datetime.now().isoformat()
        }).execute()

    return render_template('view_results.html',
                           department=department,
                           results=results)


@app.route('/vote_receipt')
def vote_receipt():
    if 'school_id' not in session:
        return redirect('/login')

    school_id = session['school_id']
    now = datetime.utcnow()

    ENABLE_RECEIPT_TIMEOUT = True
    if ENABLE_RECEIPT_TIMEOUT:
        log_resp = supabase.table("receipt_access_logs").select("*") \
            .eq("school_id", school_id).eq("status", "active") \
            .order("viewed_at", desc=True).limit(1).execute()
        log = log_resp.data[0] if log_resp.data else None

        if not log:
            supabase.table("receipt_access_logs").insert({
                "school_id":
                school_id,
                "viewed_at":
                now.isoformat(),
                "expired_at": (now + timedelta(minutes=5)).isoformat(),
                "status":
                "active"
            }).execute()
        else:
            expiry = datetime.fromisoformat(log['expired_at'])
            if now > expiry:
                supabase.table("receipt_access_logs") \
                    .update({"status": "expired"}).eq("id", log['id']).execute()
                return "<h1>Receipt viewing time expired.</h1>"

    user_resp = supabase.table("user").select(
        "school_id, first_name, last_name, course, track, year_level, department"
    ).eq("school_id", school_id).single().execute()
    user = user_resp.data

    def mask_name(name):
        return name[:4] + '*' * (len(name) - 4) if len(name) > 4 else name

    masked_first = mask_name(user['first_name']) if user else ''
    masked_last = mask_name(user['last_name']) if user else ''
    course = user.get('course', '')
    track = user.get('track', '')
    year_level = user.get('year_level', '')
    department = user.get('department', '')

    pos_resp = supabase.table("positions").select("*") \
        .eq("department", department).execute()
    all_positions = pos_resp.data if pos_resp.data else []

    votes_resp = supabase.table("votes").select("position_id, candidate_id") \
        .eq("student_id", school_id).execute()
    voted = votes_resp.data if votes_resp.data else []
    voted_map = {}
    for v in voted:
        try:
            decrypted_cid = int(decrypt_vote(v['candidate_id']))
            voted_map[v['position_id']] = decrypted_cid
        except Exception:
            continue

    vote_entries = []

    for pos in all_positions:
        pos_id = pos['id']
        position_name = pos['name']
        candidate_id = voted_map.get(pos_id)

        if candidate_id:
            cand_resp = supabase.table("candidates").select("name") \
                .eq("id", candidate_id).single().execute()
            cand = cand_resp.data
            if cand:
                masked_cand_name = mask_name(cand['name'])
                vote_hash = hashlib.sha256(
                    f"{school_id}:{pos_id}:{candidate_id}".encode()).hexdigest(
                    )
                vote_entries.append({
                    "position_name": position_name,
                    "masked_candidate": masked_cand_name,
                    "hash": vote_hash
                })
            else:
                vote_entries.append({
                    "position_name": position_name,
                    "masked_candidate": "Vote data error",
                    "hash": "-"
                })
        else:
            cand_count = supabase.table("candidates").select("id") \
                .eq("position_id", pos_id).execute()
            if not cand_count.data:
                vote_entries.append({
                    "position_name":
                    position_name,
                    "masked_candidate":
                    "No vote recorded (no candidates available)",
                    "hash":
                    hashlib.sha256(f"{school_id}:{pos_id}:nocandidate".encode(
                    )).hexdigest()
                })
            else:
                vote_entries.append({
                    "position_name":
                    position_name,
                    "masked_candidate":
                    "No vote recorded (you skipped this)",
                    "hash":
                    hashlib.sha256(
                        f"{school_id}:{pos_id}:skipped".encode()).hexdigest()
                })

    # Log vote receipt access
    user_id = None
    if user_resp.data:
        # Get the actual numeric user ID
        user_lookup = supabase.table('user').select('id').eq(
            'school_id', school_id).single().execute()
        if user_lookup.data:
            user_id = user_lookup.data['id']

    supabase.table("logs").insert({
        "user_id": user_id,
        "action": "VIEW_VOTE_RECEIPT",
        "table_name": "votes",
        "query_type": "READ",
        "target": f"Department: {department}",
        "new_data": f"Vote hashes: {[v['hash'] for v in vote_entries]}",
        "timestamp": datetime.now().isoformat()
    }).execute()

    return render_template(
        "receipts_page.html",
        masked_first=masked_first,
        masked_last=masked_last,
        course=course,
        track=track,
        year_level=year_level,
        department=department,
        hashed_users=[hashlib.sha256(school_id.encode()).hexdigest()],
        vote_entries=vote_entries,
        receipt_timeout_enabled=ENABLE_RECEIPT_TIMEOUT,
        receipt_expiry=(now +
                        timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))


@app.route('/manage_poll', methods=['GET', 'POST'])
def manage_poll():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin_resp = supabase.table('user').select('*').eq(
        'school_id', session['school_id']).single().execute()
    admin = admin_resp.data
    admin_department = admin.get('department', admin.get('course',
                                                         '')) if admin else ''
    message = ""

    # ----- Filing period logic -----
    filing_start = None
    filing_end = None
    filing_start_iso = ''
    filing_end_iso = ''
    filing_open = False

    try:
        settings_resp = supabase.table('settings').select(
            'filing_start', 'filing_end').order('id',
                                                desc=True).limit(1).execute()
        if settings_resp.data:
            filing_start = settings_resp.data[0]['filing_start']
            filing_end = settings_resp.data[0]['filing_end']

        now_ph = datetime.now(PH_TZ)
        if filing_start and filing_end:
            filing_start_dt = datetime.fromisoformat(
                filing_start.replace('Z', '+00:00')).astimezone(PH_TZ)
            filing_end_dt = datetime.fromisoformat(
                filing_end.replace('Z', '+00:00')).astimezone(PH_TZ)
            filing_open = filing_start_dt <= now_ph < filing_end_dt
            filing_start_iso = filing_start_dt.isoformat()
            if filing_open:
                filing_end_iso = filing_end_dt.isoformat()
            else:
                filing_end_iso = filing_end_dt.isoformat()
    except Exception as e:
        print(f"[ERROR] Filing period parsing failed: {e}")
        filing_open = False
        filing_start_iso = ''
        filing_end_iso = ''

    # ----- Add position -----
    if request.method == 'POST' and 'position_name' in request.form:
        if not filing_open:
            message = "You can only add positions during the filing period."
        else:
            position_name = request.form.get('position_name', '').strip()
            if position_name:
                supabase.table('positions').insert({
                    'name':
                    position_name,
                    'department':
                    admin_department
                }).execute()
                supabase.table('logs').insert({
                    'user_id':
                    admin['id'],
                    'action':
                    'ADD_POSITION',
                    'table_name':
                    'positions',
                    'query_type':
                    'INSERT',
                    'target':
                    position_name,
                    'new_data':
                    f"Department: {admin_department}",
                    'timestamp':
                    datetime.now().isoformat()
                }).execute()
                message = "Position added successfully!"

    # ----- Add candidate -----
    if request.method == 'POST' and 'candidate_name' in request.form and 'position_id' in request.form:
        if not filing_open:
            message = "You can only add candidates during the filing period."
        else:
            candidate_name = request.form.get('candidate_name', '').strip()
            position_id = request.form.get('position_id')
            campaign_message = request.form.get('campaign_message', '').strip()
            year_level = request.form.get('year_level', '').strip()
            course = request.form.get('course', '').strip()
            skills = request.form.get('skills', '').strip()
            platform = request.form.get('platform', '').strip()
            goals = request.form.get('goals', '').strip()
            sg_years = request.form.get('sg_years', '').strip()
            previous_role = request.form.get('previous_role', '').strip()
            experience = request.form.get('experience', '').strip()
            achievements = request.form.get('achievements', '').strip()
            slogan = request.form.get('slogan', '').strip()
            note = request.form.get('note', '').strip()
            image_path = ''

            # --- DUPLICATE CHECK ---
            dup_resp = supabase.table('candidates') \
                .select('id') \
                .eq('department', admin_department) \
                .ilike('name', candidate_name) \
                .execute()
            if dup_resp.data:
                message = "A candidate with this name already exists in this department."
            else:
                file = request.files.get('candidate_image')
                if file and file.filename:
                    allowed_types = {'image/jpeg', 'image/png', 'image/gif'}
                    if file.mimetype not in allowed_types:
                        message = "Only JPG, PNG, and GIF files are allowed."
                    elif len(file.read()) > 5 * 1024 * 1024:
                        message = "Image size must be less than 5MB."
                    else:
                        file.seek(0)
                        os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
                        filename = secure_filename(
                            f"{position_id}_{file.filename}")
                        image_path = f"uploads/candidates/{filename}"
                        full_save_path = os.path.join(app.root_path, 'static',
                                                      'uploads', 'candidates',
                                                      filename)
                        file.save(full_save_path)

                if candidate_name and position_id and not message:
                    supabase.table('candidates').insert({
                        'position_id':
                        int(position_id),
                        'name':
                        candidate_name,
                        'image':
                        image_path,
                        'campaign_message':
                        campaign_message,
                        'department':
                        admin_department,
                        'year_level':
                        year_level,
                        'course':
                        course,
                        'skills':
                        skills,
                        'platform':
                        platform,
                        'goals':
                        goals,
                        'sg_years':
                        sg_years,
                        'previous_role':
                        previous_role,
                        'experience':
                        experience,
                        'achievements':
                        achievements,
                        'slogan':
                        slogan,
                        'note':
                        note
                    }).execute()

                    supabase.table('logs').insert({
                        'user_id':
                        admin['id'],
                        'action':
                        'ADD_CANDIDATE',
                        'table_name':
                        'candidates',
                        'query_type':
                        'INSERT',
                        'target':
                        f"Position ID: {position_id}",
                        'new_data':
                        f"Name: {candidate_name}, Year: {year_level}, Course: {course}",
                        'timestamp':
                        datetime.now().isoformat()
                    }).execute()
                    message = "Candidate added successfully!"

    # ----- Load positions and candidates -----
    positions_resp = supabase.table('positions').select('*').eq(
        'department', admin_department).execute()
    positions = positions_resp.data if positions_resp.data else []

    candidates_per_position = {}
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates_per_position[
            pos['id']] = cands_resp.data if cands_resp.data else []

    return render_template('admin_manage_poll.html',
                           admin_department=admin_department,
                           message=message,
                           positions=positions,
                           candidates_per_position=candidates_per_position,
                           filing_start_iso=filing_start_iso,
                           filing_end_iso=filing_end_iso,
                           filing_open=filing_open)


@app.route('/manage_candidates', methods=['GET', 'POST'])
def manage_candidates():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin_school_id = session.get('school_id')
    admin_data = supabase.table('user') \
        .select('department') \
        .eq('school_id', admin_school_id) \
        .single().execute().data

    if not admin_data:
        return "Admin not found", 404

    department = admin_data.get('department')
    if not department:
        return "Admin has no department assigned", 400

    # Fetch filing period settings
    settings_resp = supabase.table('settings') \
        .select('filing_start', 'filing_end') \
        .eq('department', department).order('id', desc=True).limit(1).execute()

    if not settings_resp.data:
        settings_resp = supabase.table('settings') \
            .select('filing_start', 'filing_end') \
            .eq('department', 'ALL').order('id', desc=True).limit(1).execute()

    settings_row = settings_resp.data[0] if settings_resp.data else None
    filing_start = settings_row['filing_start'] if settings_row else None
    filing_end = settings_row['filing_end'] if settings_row else None

    filing_start_display = format_ph_time(
        filing_start) if filing_start else 'Not set'
    filing_end_display = format_ph_time(
        filing_end) if filing_end else 'Not set'

    # Filing period logic
    filing_start_iso = ''
    filing_end_iso = ''
    filing_open = False

    now_ph = datetime.now(PH_TZ)
    if filing_start and filing_end:
        try:
            filing_start_dt = datetime.fromisoformat(
                filing_start.replace('Z', '+00:00')).astimezone(PH_TZ)
            filing_end_dt = datetime.fromisoformat(
                filing_end.replace('Z', '+00:00')).astimezone(PH_TZ)
            filing_open = filing_start_dt <= now_ph < filing_end_dt
            filing_start_iso = filing_start_dt.isoformat()
            if filing_open:
                filing_end_iso = filing_end_dt.isoformat()
            else:
                filing_end_iso = filing_end_dt.isoformat()
        except Exception as e:
            print(f"Error parsing filing period: {e}")
            filing_open = False
            filing_start_iso = ''
            filing_end_iso = ''

    # Handle form submission
    if request.method == 'POST':
        if not filing_open:
            flash(
                "Candidate/position management is only allowed during the filing period.",
                "error")
            return redirect(url_for('manage_candidates'))

        if 'add_candidate' in request.form:
            name = request.form.get('name', '').strip()
            position_id = request.form.get('position_id')
            campaign_message = request.form.get('campaign_message', '').strip()
            year_level = request.form.get('year_level', '').strip()
            course = request.form.get('course', '').strip()
            skills = request.form.get('skills', '').strip()
            platform = request.form.get('platform', '').strip()
            goals = request.form.get('goals', '').strip()
            sg_years = request.form.get('sg_years', '').strip()
            previous_role = request.form.get('previous_role', '').strip()
            experience = request.form.get('experience', '').strip()
            achievements = request.form.get('achievements', '').strip()
            slogan = request.form.get('slogan', '').strip()
            note = request.form.get('note', '').strip()
            image_path = None

            # --- DUPLICATE CHECK ---
            dup_resp = supabase.table('candidates') \
                .select('id') \
                .eq('department', department) \
                .ilike('name', name) \
                .execute()
            if dup_resp.data:
                flash(
                    "A candidate with this name already exists in this department.",
                    "error")
                return redirect(url_for('manage_candidates'))

            file = request.files.get('image')
            if file and file.filename:
                os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
                filename = secure_filename(f"{position_id}_{file.filename}")
                image_path = f"uploads/candidates/{filename}"
                full_save_path = os.path.join(app.root_path, 'static',
                                              'uploads', 'candidates',
                                              filename)
                file.save(full_save_path)

            supabase.table('candidates').insert({
                'position_id': int(position_id),
                'name': name,
                'image': image_path,
                'campaign_message': campaign_message,
                'department': department,
                'year_level': year_level,
                'course': course,
                'skills': skills,
                'platform': platform,
                'goals': goals,
                'sg_years': sg_years,
                'previous_role': previous_role,
                'experience': experience,
                'achievements': achievements,
                'slogan': slogan,
                'note': note
            }).execute()

            supabase.table('logs').insert({
                'user_id':
                session.get('user_id'),
                'action':
                'ADD_CANDIDATE',
                'table_name':
                'candidates',
                'query_type':
                'INSERT',
                'target':
                name,
                'new_data':
                f"Position ID: {position_id}, Department: {department}",
                'timestamp':
                datetime.now(PH_TZ).isoformat()
            }).execute()

            flash("Candidate added successfully!", "success")
            return redirect(url_for('manage_candidates'))

    # Load data for rendering
    positions_resp = supabase.table('positions') \
        .select('*').eq('department', department) \
        .order('name', desc=False).execute()
    positions = positions_resp.data or []

    candidates_resp = supabase.table('candidates') \
        .select('*,positions(name)').eq('department', department).execute()
    candidates = candidates_resp.data or []

    return render_template('admin_manage_candidates.html',
                           filing_start_display=filing_start_display,
                           filing_end_display=filing_end_display,
                           filing_start_iso=filing_start_iso,
                           filing_end_iso=filing_end_iso,
                           positions=positions,
                           candidates=candidates,
                           filing_open=filing_open)


@app.route('/set_filing_period', methods=['POST'])
def set_filing_period():
    if 'school_id' not in session or session.get('role') != 'SysAdmin':
        flash("You must be a system admin to access this page.", "danger")
        return redirect(url_for('login'))

    # Fetch current period to check if setting is allowed
    settings_resp = supabase.table('settings').select('filing_start', 'filing_end') \
        .eq('department', 'ALL').order('id', desc=True).limit(1).execute()
    settings_row = settings_resp.data[0] if settings_resp.data else None

    filing_start = settings_row['filing_start'] if settings_row else ''
    filing_end = settings_row['filing_end'] if settings_row else ''

    # Only allow setting if no period set (not if expired)
    can_set = not filing_start or not filing_end

    if not can_set:
        flash("You cannot change the filing period once it is set.", "danger")
        return redirect(url_for('system_admin'))

    # Get form data
    start_date = request.form.get('filing_start_date')
    start_time = request.form.get('filing_start_time')
    end_date = request.form.get('filing_end_date')
    end_time = request.form.get('filing_end_time')

    try:
        start_dt = datetime.strptime(f"{start_date} {start_time}",
                                     "%Y-%m-%d %H:%M").replace(tzinfo=PH_TZ)
        end_dt = datetime.strptime(f"{end_date} {end_time}",
                                   "%Y-%m-%d %H:%M").replace(tzinfo=PH_TZ)
        start_utc = start_dt.astimezone(timezone.utc).isoformat()
        end_utc = end_dt.astimezone(timezone.utc).isoformat()
    except Exception:
        flash("Invalid date or time format.", "danger")
        return redirect(url_for('system_admin'))

    # Get all unique departments from positions
    departments_resp = supabase.table('positions').select(
        'department').execute()
    departments = {d['department']
                   for d in departments_resp.data
                   } if departments_resp.data else set()

    # Update or insert filing period for each department
    for dept in departments:
        dept_settings = supabase.table('settings').select('id').eq(
            'department', dept).execute()
        if dept_settings.data:
            supabase.table('settings').update({
                'filing_start': start_utc,
                'filing_end': end_utc
            }).eq('id', dept_settings.data[0]['id']).execute()
        else:
            supabase.table('settings').insert({
                'department': dept,
                'filing_start': start_utc,
                'filing_end': end_utc
            }).execute()

    # Update or insert for 'ALL' department
    all_settings = supabase.table('settings').select('id').eq(
        'department', 'ALL').execute()
    if all_settings.data:
        supabase.table('settings').update({
            'filing_start': start_utc,
            'filing_end': end_utc
        }).eq('id', all_settings.data[0]['id']).execute()
    else:
        supabase.table('settings').insert({
            'department': 'ALL',
            'filing_start': start_utc,
            'filing_end': end_utc
        }).execute()

    flash("Filing period set for all departments!", "success")
    return redirect(url_for('system_admin'))


# ...existing code...
#for voting
@app.route('/set_voting_period', methods=['GET', 'POST'])
def set_voting_period():
    if 'school_id' not in session or session.get('role') != 'SysAdmin':
        flash("You must be a system admin to access this page.", "danger")
        return redirect(url_for('login'))

    # Fetch latest 'ALL' department voting period settings
    settings_resp = supabase.table('settings').select('start_time', 'end_time') \
        .eq('department', 'ALL').order('id', desc=True).limit(1).execute()
    settings_row = settings_resp.data[0] if settings_resp.data else None

    voting_start = settings_row['start_time'] if settings_row else ''
    voting_end = settings_row['end_time'] if settings_row else ''

    def safe_format(dt_str):
        if not dt_str:
            return 'Not set'
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            dt = dt.astimezone(PH_TZ)
            return dt.strftime('%B %d, %Y %I:%M%p')
        except Exception:
            return 'Invalid date'

    voting_start_display = safe_format(voting_start)
    voting_end_display = safe_format(voting_end)

    # Only allow setting if no period set or period has expired
    now_utc = datetime.now(timezone.utc)
    can_set = False
    if not voting_start or not voting_end:
        can_set = True
    else:
        try:
            voting_end_dt = datetime.fromisoformat(
                voting_end.replace('Z', '+00:00'))
            if now_utc > voting_end_dt.astimezone(timezone.utc):
                can_set = True
        except Exception:
            can_set = False

    if request.method == 'POST':
        if not can_set:
            flash("You cannot change the voting period while it is active.",
                  "danger")
            return redirect(url_for('set_voting_period'))

        start_date = request.form.get('voting_start_date')
        start_time = request.form.get('voting_start_time')
        end_date = request.form.get('voting_end_date')
        end_time = request.form.get('voting_end_time')

        try:
            start_dt = datetime.strptime(
                f"{start_date} {start_time}",
                "%Y-%m-%d %H:%M").replace(tzinfo=PH_TZ)
            end_dt = datetime.strptime(f"{end_date} {end_time}",
                                       "%Y-%m-%d %H:%M").replace(tzinfo=PH_TZ)
            start_utc = start_dt.astimezone(timezone.utc).isoformat()
            end_utc = end_dt.astimezone(timezone.utc).isoformat()
        except Exception:
            flash("Invalid date or time format.", "danger")
            return redirect(url_for('set_voting_period'))

        # Get all unique departments from positions
        departments_resp = supabase.table('positions').select(
            'department').execute()
        departments = {d['department']
                       for d in departments_resp.data
                       } if departments_resp.data else set()

        # Update or insert voting period for each department
        for dept in departments:
            dept_settings = supabase.table('settings').select('id').eq(
                'department', dept).execute()
            if dept_settings.data:
                supabase.table('settings').update({
                    'start_time': start_utc,
                    'end_time': end_utc
                }).eq('id', dept_settings.data[0]['id']).execute()
            else:
                supabase.table('settings').insert({
                    'department': dept,
                    'start_time': start_utc,
                    'end_time': end_utc
                }).execute()

        # Update or insert for 'ALL' department
        all_settings = supabase.table('settings').select('id').eq(
            'department', 'ALL').execute()
        if all_settings.data:
            supabase.table('settings').update({
                'start_time': start_utc,
                'end_time': end_utc
            }).eq('id', all_settings.data[0]['id']).execute()
        else:
            supabase.table('settings').insert({
                'department': 'ALL',
                'start_time': start_utc,
                'end_time': end_utc
            }).execute()

        flash("Voting period set for all departments!", "success")
        return redirect(url_for('set_voting_period'))

    return render_template("system_voting_admin.html",
                           voting_start=voting_start,
                           voting_end=voting_end,
                           voting_start_display=voting_start_display,
                           voting_end_display=voting_end_display,
                           can_set=can_set)


# ...existing code...


@app.route('/edit_candidate/<int:id>', methods=['GET', 'POST'])
def edit_candidate(id):
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    cand_resp = supabase.table('candidates').select('*').eq(
        'id', id).single().execute()
    candidate = cand_resp.data
    positions_resp = supabase.table('positions').select('*').order(
        'name', desc=False).execute()
    positions = positions_resp.data if positions_resp.data else []

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        position_id = request.form.get('position_id')
        campaign_message = request.form.get('campaign_message', '').strip()
        year_level = request.form.get('year_level', '').strip()
        course = request.form.get('course', '').strip()
        skills = request.form.get('skills', '').strip()
        platform = request.form.get('platform', '').strip()
        goals = request.form.get('goals', '').strip()
        sg_years = request.form.get('sg_years', '').strip()
        previous_role = request.form.get('previous_role', '').strip()
        experience = request.form.get('experience', '').strip()
        achievements = request.form.get('achievements', '').strip()
        slogan = request.form.get('slogan', '').strip()
        note = request.form.get('note', '').strip()
        image_path = candidate['image']

        file = request.files.get('image')
        if file and file.filename:
            if image_path:
                old_path = os.path.join('static', image_path)
                if os.path.exists(old_path):
                    os.remove(old_path)
            os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
            filename = secure_filename(f"{position_id}_{file.filename}")
            image_path = f"uploads/candidates/{filename}"
            full_save_path = os.path.join(app.root_path, 'static', 'uploads',
                                          'candidates', filename)
            file.save(full_save_path)

        supabase.table('candidates').update({
            'name': name,
            'position_id': int(position_id),
            'campaign_message': campaign_message,
            'image': image_path,
            'year_level': year_level,
            'course': course,
            'skills': skills,
            'platform': platform,
            'goals': goals,
            'sg_years': sg_years,
            'previous_role': previous_role,
            'experience': experience,
            'achievements': achievements,
            'slogan': slogan,
            'note': note
        }).eq('id', id).execute()

        supabase.table('logs').insert({
            'user_id': session.get('user_id'),
            'action': 'EDIT_CANDIDATE',
            'table_name': 'candidates',
            'query_type': 'UPDATE',
            'target': name,
            'new_data': f"Candidate ID: {id}, New Position ID: {position_id}",
            'timestamp': datetime.now().isoformat()
        }).execute()

        flash("Candidate updated successfully!", "success")
        return redirect(url_for('manage_candidates'))

    return render_template('edit_candidate.html',
                           candidate=candidate,
                           positions=positions)


@app.route('/delete_candidate/<int:id>')
def delete_candidate(id):
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    cand_resp = supabase.table('candidates').select('*').eq(
        'id', id).single().execute()
    candidate = cand_resp.data
    if candidate:
        if candidate['image']:
            image_path = os.path.join('static', candidate['image'])
            if os.path.exists(image_path):
                os.remove(image_path)
        supabase.table('candidates').delete().eq('id', id).execute()
        supabase.table('logs').insert({
            'user_id': session.get('user_id'),
            'action': 'DELETE_CANDIDATE',
            'table_name': 'candidates',
            'query_type': 'DELETE',
            'target': f"Candidate ID: {id}",
            'new_data': f"Name: {candidate['name']}",
            'timestamp': datetime.now().isoformat()
        }).execute()

        flash("Candidate deleted successfully!", "success")
    else:
        flash("Candidate not found.", "danger")
    return redirect(url_for('manage_candidates'))


@app.route('/manage_students')
def manage_students():
    if session.get('role') != 'admin':
        return redirect('/')

    admin_school_id = session.get('school_id')
    if not admin_school_id:
        return "Missing school ID in session", 400

    admin_data = supabase.table('user') \
        .select('department') \
        .eq('school_id', admin_school_id) \
        .single() \
        .execute().data

    if not admin_data:
        return "Admin not found", 404

    department = admin_data.get('department')
    if not department:
        return "Admin has no department assigned", 400

    resp = supabase.table('pending_users') \
        .select('*') \
        .eq('department', department) \
        .order('submitted_at', desc=True) \
        .execute()

    pending_users = resp.data or []
    return render_template('admin_manage_students.html', users=pending_users)


@app.route('/approve_user/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    user = supabase.table('pending_users').select('*').eq(
        'id', user_id).single().execute().data
    if not user:
        return "User not found", 404

    hashed_pw = generate_password_hash(user['password_plain'], method='scrypt')
    supabase.table('user').insert({
        'school_id': user['school_id'],
        'department': user.get('department', ''),
        'course': user['course'],
        'course_code': user.get('course_code', ''),
        'track': user.get('track', ''),
        'year_level': user.get('year_level', ''),
        'email': user['email'],
        'password_hash': hashed_pw,
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'phone': user['phone'],
        'id_photo_front': user['id_photo_front'],
        'id_photo_back': user['id_photo_back'],
        'role': 'user'
    }).execute()

    supabase.table('logs').insert({
        'user_id': session.get('user_id'),
        'action': 'APPROVE_USER',
        'table_name': 'user',
        'query_type': 'INSERT',
        'target': f"Pending User ID: {user_id}",
        'new_data': f"School ID: {user['school_id']}, Email: {user['email']}",
        'timestamp': datetime.now().isoformat()
    }).execute()

    # Send approval email
    send_approval_email(user['email'], user.get('first_name', ''))

    supabase.table('pending_users').delete().eq('id', user_id).execute()
    supabase.table('logs').insert({
        'user_id': session.get('user_id'),
        'action': 'DELETE_PENDING_USER',
        'table_name': 'pending_users',
        'query_type': 'DELETE',
        'target': f"Pending User ID: {user_id}",
        'new_data': f"Reason: approved",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return redirect(url_for('manage_students'))


@app.route('/reject_user/<int:user_id>', methods=['POST'])
def reject_user(user_id):
    user = supabase.table('pending_users').select('*').eq(
        'id', user_id).single().execute().data
    if user:
        # Send rejection email
        send_rejection_email(user['email'], user.get('first_name', ''))
    supabase.table('pending_users').delete().eq('id', user_id).execute()
    supabase.table('logs').insert({
        'user_id': session.get('user_id'),
        'action': 'REJECT_USER',
        'table_name': 'pending_users',
        'query_type': 'DELETE',
        'target': f"Pending User ID: {user_id}",
        'new_data': f"Email: {user['email'] if user else 'unknown'}",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return redirect(url_for('manage_students'))


@app.route('/manage_settings', methods=['GET', 'POST'])
def manage_settings():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin_resp = supabase.table('user').select('*').eq(
        'school_id', session['school_id']).single().execute()
    admin = admin_resp.data
    admin_department = admin.get('department', admin.get('course',
                                                         '')) if admin else ''
    message = ""
    voting_start = None
    voting_end = None

    # Load latest voting period
    setting_resp = supabase.table('settings').select('*').eq(
        'department', admin_department).order('id',
                                              desc=True).limit(1).execute()
    if setting_resp.data:
        setting = setting_resp.data[0]
        start_str = setting.get('start_time')
        end_str = setting.get('end_time')
        try:
            if start_str:
                voting_start = datetime.fromisoformat(start_str)
                if voting_start.tzinfo is None:
                    voting_start = voting_start.replace(tzinfo=PH_TZ)
            if end_str:
                voting_end = datetime.fromisoformat(end_str)
                if voting_end.tzinfo is None:
                    voting_end = voting_end.replace(tzinfo=PH_TZ)
        except Exception:
            voting_start = None
            voting_end = None

    can_set = not voting_start or not voting_end

    if request.method == 'POST':
        if not can_set:
            flash("Voting period can only be set once and cannot be changed.",
                  "danger")
            return redirect(url_for('manage_settings'))
        start_str = request.form.get('voting_start')
        end_str = request.form.get('voting_end')
        if start_str and end_str:
            try:
                start_dt = datetime.strptime(
                    start_str, "%Y-%m-%dT%H:%M").replace(tzinfo=PH_TZ)
                end_dt = datetime.strptime(
                    end_str, "%Y-%m-%dT%H:%M").replace(tzinfo=PH_TZ)
                supabase.table('settings').insert({
                    'department':
                    admin_department,
                    'start_time':
                    start_dt.isoformat(),
                    'end_time':
                    end_dt.isoformat()
                }).execute()
                supabase.table('logs').insert({
                    'user_id':
                    admin['id'],
                    'action':
                    'SET_VOTING_PERIOD',
                    'table_name':
                    'settings',
                    'query_type':
                    'INSERT',
                    'target':
                    f"Department: {admin_department}",
                    'new_data':
                    f"Start: {start_dt.isoformat()}, End: {end_dt.isoformat()}",
                    'timestamp':
                    datetime.now().isoformat()
                }).execute()
                voting_start = start_dt
                voting_end = end_dt
                message = f"Voting period set for {admin_department}!"
                can_set = False
            except Exception:
                voting_start = None
                voting_end = None
                message = "Invalid date format."

    return render_template('admin_manage_settings.html',
                           admin_department=admin_department,
                           voting_start=voting_start,
                           voting_end=voting_end,
                           message=message,
                           can_set=can_set)


@app.route('/get_logs')
def get_logs():
    try:
        response = supabase.table('logs').select('*').order(
            'timestamp', desc=True).limit(100).execute()
        logs = response.data or []
        supabase.table('logs').insert({
            'user_id': session.get('user_id'),
            'action': 'FETCH_LOGS',
            'table_name': 'logs',
            'query_type': 'SELECT',
            'target': 'Last 100 log entries',
            'new_data': '',
            'timestamp': datetime.now().isoformat()
        }).execute()

        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/activity')
def activity():
    if 'school_id' not in session:
        flash("You must be logged in to view activity.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    role = session.get('role', 'user')

    # Get current user info
    user_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    current_user = user_resp.data
    if not current_user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    department = current_user.get('department', current_user.get('course', ''))

    # Fetch logs based on role
    if role == 'admin':
        # Admin sees user activity in their department
        # Get all users in the same department
        dept_users_resp = supabase.table('user').select(
            'id, school_id, first_name, last_name').eq('department',
                                                       department).execute()
        dept_user_ids = [u['id'] for u in dept_users_resp.data if u.get('id')]

        if dept_user_ids:
            logs_resp = supabase.table('logs').select('*').in_(
                'user_id', dept_user_ids).order('timestamp',
                                                desc=True).limit(50).execute()
        else:
            logs_resp = supabase.table('logs').select('*').eq(
                'user_id', -1).execute()  # Empty result

        activity_logs = logs_resp.data or []

        # Create user lookup for names
        user_lookup = {u['id']: u for u in dept_users_resp.data}

        # Format logs for admin view
        formatted_logs = []
        for log in activity_logs:
            user_info = user_lookup.get(log['user_id'], {})
            user_name = f"{user_info.get('first_name', 'Unknown')} {user_info.get('last_name', '')}"
            school_id_info = user_info.get('school_id', 'N/A')

            # Create readable message based on action
            if log['action'] == 'CAST_VOTE':
                message = f"User {user_name} ({school_id_info}) cast a vote"
            elif log['action'] == 'LOGIN_SUCCESS':
                message = f"User {user_name} ({school_id_info}) logged in"
            elif log['action'] == 'LOGOUT':
                message = f"User {user_name} ({school_id_info}) logged out"
            elif log['action'] == 'VIEW_CANDIDATES':
                message = f"User {user_name} ({school_id_info}) viewed candidates"
            elif log['action'] == 'VIEW_CANDIDATE_DETAILS':
                message = f"User {user_name} ({school_id_info}) viewed candidate details"
            elif log['action'] == 'VIEW_ELECTION_RESULTS':
                message = f"User {user_name} ({school_id_info}) viewed election results"
            elif log['action'] == 'VIEW_VOTE_RECEIPT':
                message = f"User {user_name} ({school_id_info}) viewed vote receipt"
            elif log['action'] == 'PASSWORD_RESET':
                message = f"User {user_name} ({school_id_info}) reset their password"
            else:
                message = f"User {user_name} ({school_id_info}) performed: {log['action']}"

            formatted_logs.append({
                'timestamp': log['timestamp'],
                'message': message,
                'action': log['action']
            })

    else:
        # User sees admin activity in their department
        # Get all admins in the same department
        dept_admins_resp = supabase.table(
            'user').select('id, school_id, first_name, last_name').eq(
                'department', department).eq('role', 'admin').execute()
        dept_admin_ids = [
            a['id'] for a in dept_admins_resp.data if a.get('id')
        ]

        if dept_admin_ids:
            logs_resp = supabase.table('logs').select('*').in_(
                'user_id',
                dept_admin_ids).order('timestamp',
                                      desc=True).limit(50).execute()
        else:
            logs_resp = supabase.table('logs').select('*').eq(
                'user_id', -1).execute()  # Empty result

        activity_logs = logs_resp.data or []

        # Create admin lookup for names
        admin_lookup = {a['id']: a for a in dept_admins_resp.data}

        # Format logs for user view
        formatted_logs = []
        for log in activity_logs:
            admin_info = admin_lookup.get(log['user_id'], {})
            admin_name = f"{admin_info.get('first_name', 'Unknown')} {admin_info.get('last_name', '')}"

            # Create readable message based on action
            if log['action'] == 'ADD_POSITION':
                message = f"Admin {admin_name} added a new position: {log.get('target', 'Unknown')}"
            elif log['action'] == 'ADD_CANDIDATE':
                candidate_name = log.get('new_data', '').split(
                    'Name: ')[1].split(',')[0] if 'Name: ' in log.get(
                        'new_data', '') else 'Unknown'
                message = f"Admin {admin_name} added candidate: {candidate_name}"
            elif log['action'] == 'EDIT_CANDIDATE':
                message = f"Admin {admin_name} edited candidate: {log.get('target', 'Unknown')}"
            elif log['action'] == 'DELETE_CANDIDATE':
                candidate_name = log.get(
                    'new_data', '').split('Name: ')[1] if 'Name: ' in log.get(
                        'new_data', '') else 'Unknown'
                message = f"Admin {admin_name} deleted candidate: {candidate_name}"
            elif log['action'] == 'APPROVE_USER':
                message = f"Admin {admin_name} approved a new user registration"
            elif log['action'] == 'REJECT_USER':
                message = f"Admin {admin_name} rejected a user registration"
            elif log['action'] == 'UPDATE_VOTING_DEADLINE':
                deadline = log.get('new_data', '').split(
                    'Deadline set to: ')[1] if 'Deadline set to: ' in log.get(
                        'new_data', '') else 'Unknown'
                message = f"Admin {admin_name} updated voting deadline"
            elif log['action'] == 'VIEW_ADMIN_DASHBOARD':
                message = f"Admin {admin_name} accessed admin dashboard"
            else:
                message = f"Admin {admin_name} performed: {log['action']}"

            formatted_logs.append({
                'timestamp': log['timestamp'],
                'message': message,
                'action': log['action']
            })

    # Log this activity view
    supabase.table('logs').insert({
        'user_id': current_user['id'],
        'action': 'VIEW_ACTIVITY_LOGS',
        'table_name': 'logs',
        'query_type': 'READ',
        'target': f"Role: {role}, Department: {department}",
        'new_data': f"Viewed {len(formatted_logs)} activity logs",
        'timestamp': datetime.now().isoformat()
    }).execute()

    return render_template(
        'activity.html',
        logs=formatted_logs,
        role=role,
        department=department,
        user_name=
        f"{current_user.get('first_name', '')} {current_user.get('last_name', '')}"
    )


@app.route('/voting_statistics')
def voting_statistics():
    # --- Access Control ---
    role = session.get('role')
    if role not in ['SysAdmin', 'admin']:
        abort(403)

    print("📥 [INFO] Fetching users and votes from Supabase...")

    # Fetch data
    users_response = supabase.table("user").select(
        "id", "school_id", "department", "course",
        "year_level").eq("role", "user").execute()
    votes_response = supabase.table("votes").select("student_id").execute()

    users = users_response.data or []
    votes = votes_response.data or []

    print(f"✅ [DATA] Users: {len(users)}, Votes: {len(votes)}")

    user_ids = {u['school_id'] for u in users}
    voted_ids = {v['student_id'] for v in votes if v['student_id'] in user_ids}

    total_users = len(user_ids)
    total_voted = len(voted_ids)
    total_not_voted = total_users - total_voted

    turnout_percentage = round(
        (total_voted / total_users) * 100, 2) if total_users else 0
    not_voted_percentage = round(100 - turnout_percentage, 2)

    print(
        f"📈 Turnout: {turnout_percentage}%, Not Voted: {not_voted_percentage}%"
    )

    # ---------------------- DEPARTMENT STATS ----------------------
    dept_users, dept_voted = {}, {}
    for u in users:
        d = (u.get('department') or 'Unknown').strip()
        sid = u['school_id']
        dept_users.setdefault(d, set()).add(sid)
        if sid in voted_ids:
            dept_voted.setdefault(d, set()).add(sid)

    department_stats = []
    for d in sorted(dept_users):
        t = len(dept_users[d])
        v = len(dept_voted.get(d, []))
        p = round((v / t) * 100, 2) if t else 0
        department_stats.append({
            "department": d,
            "total": t,
            "voted": v,
            "percentage": p
        })
        print(f"🏢 [DEPT] {d}: {p}% ({v}/{t})")

    # ---------------------- COURSE STATS ----------------------
    course_users, course_voted = {}, {}
    for u in users:
        c = (u.get('course') or 'Unknown').strip()
        sid = u['school_id']
        course_users.setdefault(c, set()).add(sid)
        if sid in voted_ids:
            course_voted.setdefault(c, set()).add(sid)

    course_stats, offset = [], 0
    for c in sorted(course_users):
        t = len(course_users[c])
        v = len(course_voted.get(c, []))
        p = round((v / t) * 100, 2) if t else 0
        course_stats.append({
            "course": c,
            "percentage": p,
            "offset": round(offset, 2)
        })
        offset += p
        print(f"📚 [COURSE] {c}: {p}% ({v}/{t})")

    # ---------------------- YEAR LEVEL STATS ----------------------
    def normalize_year(val):
        raw = (val or "").strip().lower()
        if "1" in raw: return "1st Year"
        if "2" in raw: return "2nd Year"
        if "3" in raw: return "3rd Year"
        if "4" in raw: return "4th Year"
        return "Unknown"

    year_colors = {
        "1st Year": "#3F51B5",
        "2nd Year": "#E91E63",
        "3rd Year": "#00BCD4",
        "4th Year": "#8BC34A",
        "Unknown": "#9E9E9E"
    }

    year_users, year_voted = {}, {}
    for u in users:
        y = normalize_year(u.get('year_level'))
        sid = u['school_id']
        year_users.setdefault(y, set()).add(sid)
        if sid in voted_ids:
            year_voted.setdefault(y, set()).add(sid)

    year_level_stats = []
    for y, color in year_colors.items():
        t = len(year_users.get(y, []))
        v = len(year_voted.get(y, []))
        p = round((v / t) * 100, 2) if t else 0
        year_level_stats.append({"Year": y, "percentage": p, "color": color})
        print(f"🎓 [YEAR] {y}: {p}% ({v}/{t})")

    print("✅ [DONE] Voting statistics ready.\n")

    return render_template("voting_statistics.html",
                           total_users=total_users,
                           total_voted=total_voted,
                           total_not_voted=total_not_voted,
                           turnout_percentage=turnout_percentage,
                           not_voted_percentage=not_voted_percentage,
                           department_stats=department_stats,
                           course_stats=course_stats,
                           year_level_stats=year_level_stats)


@app.route('/pyinfo')
def pyinfo():
    info = [
        f"Python version: {platform.python_version()}",
        f"Platform: {platform.platform()}",
        f"Executable: {sys.executable}",
        f"Implementation: {platform.python_implementation()}",
        f"System Path: {sys.path}",
        f"Loaded Modules: {list(sys.modules.keys())[:20]} ...",
    ]
    return Response("<br>".join(info), mimetype="text/html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
