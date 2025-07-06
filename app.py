#HELLO WORLD TANG INA MO PAUL BADING SI RUDY
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
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
#import secrets
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import time
import threading

PH_TZ = timezone(timedelta(hours=8))


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

RECAPTCHA_SITE_KEY = "6LdsDXgrAAAAAJzPuLgwtx1aw0F4Bb4Vnx2o-1sa"
RECAPTCHA_SECRET_KEY = "6LdsDXgrAAAAAGNoHmLuPtv3a6Z_ZhEFy7EvQnga"


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
    supabase.table('user').update({
        'reset_otp': otp,
        'reset_otp_expiry': expiry.isoformat()
    }).eq('id', user['id']).execute()
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
        # Clear OTP and set new password
        supabase.table('user').update({
            'password_hash':
            generate_password_hash(password),
            'reset_otp':
            None,
            'reset_otp_expiry':
            None
        }).eq('id', user['id']).execute()
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
                # Show redirecting message before dashboard
                if user['role'] == 'admin':
                    return render_template(
                        'redirecting.html',
                        target=url_for('admin_dashboard'),
                        message="REDIRECTING to ADMIN DASHBOARD...")
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

        short_uuid = str(uuid.uuid4())[:8]
        fake_phone = f"admin-{short_uuid}"

        supabase.table('user').insert({
            'school_id': school_id,
            'course': course,
            'email': email,
            'password_hash': password_hash,
            'first_name': first_name,
            'last_name': last_name,
            'role': 'admin',
            'phone': fake_phone,  # ✅ Now guaranteed < 20 characters
            'id_photo_front': 'N/A',
            'id_photo_back': 'N/A'
        }).execute()

        flash("Admin registered successfully!", "success")
        return redirect(url_for('register_admin'))

    return render_template('register_admin.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/system_admin')
def system_admin():
    return render_template('sysadmin.html')


# --- FINAL FIXED ROUTE (Python) ---
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
    now = datetime.now(timezone.utc)  # timezone-aware
    voting_deadline = None
    voting_closed = False

    setting_resp = supabase.table('settings').select('*').eq(
        'department',
        user.get('department',
                 user.get('course', ''))).order('id',
                                                desc=True).limit(1).execute()
    if setting_resp.data:
        voting_deadline_str = setting_resp.data[0]['voting_deadline']
        if voting_deadline_str:
            try:
                voting_deadline = datetime.fromisoformat(voting_deadline_str)
                # Ensure voting_deadline is timezone-aware
                if voting_deadline.tzinfo is None or voting_deadline.tzinfo.utcoffset(
                        voting_deadline) is None:
                    voting_deadline = voting_deadline.replace(
                        tzinfo=timezone.utc)
            except Exception:
                voting_deadline = None
        voting_closed = now > voting_deadline if voting_deadline else False

    # Handle Vote Submission
    if request.method == 'POST' and not voting_closed:
        for position_id, candidate_id in request.form.items():
            if position_id.isdigit() and candidate_id.isdigit():
                vote_resp = supabase.table('votes').select('*').eq(
                    'student_id', school_id).eq('position_id',
                                                int(position_id)).execute()
                if not vote_resp.data:
                    encrypted_candidate_id = encrypt_vote(str(candidate_id))
                    supabase.table('votes').insert({
                        'student_id':
                        school_id,
                        'position_id':
                        int(position_id),
                        'candidate_id':
                        encrypted_candidate_id,
                        'department':
                        user.get('department', user.get('course', ''))
                    }).execute()
                    # Hash the student_id before adding to blockchain
                    hashed_student_id = hashlib.sha256(
                        school_id.encode()).hexdigest()
                    vote_blockchain.add_block({
                        "student_id": hashed_student_id,
                        "position_id": int(position_id),
                        "candidate_id": encrypted_candidate_id,
                        "timestamp": str(time.time())
                    })
        flash('Your vote has been submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Fetch All Positions
    department = user.get('department', user.get('course', ''))
    positions_resp = supabase.table('positions').select('*').eq(
        'department', department).execute()
    positions = positions_resp.data if positions_resp.data else []

    # Get Candidate Data
    candidates_per_position = {}
    votable_positions = []
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates = cands_resp.data if cands_resp.data else []
        candidates_per_position[pos['id']] = candidates
        if candidates:
            votable_positions.append(pos)

    # Voted Positions
    voted_positions_resp = supabase.table('votes').select('position_id').eq(
        'student_id', school_id).execute()
    voted_positions = [v['position_id'] for v in voted_positions_resp.data
                       ] if voted_positions_resp.data else []

    all_voted = all(pos['id'] in voted_positions for pos in votable_positions)

    return render_template('dashboard.html',
                           user=user,
                           dept_logo=dept_logo,
                           voting_deadline=voting_deadline.isoformat()
                           if voting_deadline else None,
                           now=now,
                           voting_closed=voting_closed,
                           positions=positions,
                           voted_positions=voted_positions,
                           candidates_per_position=candidates_per_position,
                           all_voted=all_voted)


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
    admin_resp = supabase.table('user').select('*').eq(
        'school_id', school_id).single().execute()
    admin = admin_resp.data
    return render_template('admin_dash.html', admin=admin)


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

    if request.method == 'POST' and 'position_name' in request.form:
        position_name = request.form.get('position_name', '').strip()
        if position_name:
            supabase.table('positions').insert({
                'name': position_name,
                'department': admin_department
            }).execute()
            message = "Position added successfully!"

    if request.method == 'POST' and 'candidate_name' in request.form and 'position_id' in request.form:
        candidate_name = request.form.get('candidate_name', '').strip()
        position_id = request.form.get('position_id')
        campaign_message = request.form.get('campaign_message', '').strip()
        image_path = ''

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
                filename = secure_filename(f"{position_id}_{file.filename}")
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
                    admin_department  # add this line
                }).execute()
                message = "Candidate added successfully!"

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
                           candidates_per_position=candidates_per_position)


@app.route('/manage_candidates', methods=['GET', 'POST'])
def manage_candidates():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin_school_id = session.get('school_id')
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

    if request.method == 'POST' and 'add_candidate' in request.form:
        name = request.form.get('name', '').strip()
        position_id = request.form.get('position_id')
        campaign_message = request.form.get('campaign_message', '').strip()
        image_path = None

        file = request.files.get('image')
        if file and file.filename:
            os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
            filename = secure_filename(f"{position_id}_{file.filename}")
            image_path = f"uploads/candidates/{filename}"
            full_save_path = os.path.join(app.root_path, 'static', 'uploads',
                                          'candidates', filename)
            file.save(full_save_path)

        supabase.table('candidates').insert({
            'position_id': int(position_id),
            'name': name,
            'image': image_path,
            'campaign_message': campaign_message,
            'department': department  # ensure this field exists in the table
        }).execute()

        flash("Candidate added successfully!", "success")
        return redirect(url_for('manage_candidates'))

    positions_resp = supabase.table('positions') \
        .select('*') \
        .eq('department', department) \
        .order('name', desc=False) \
        .execute()
    positions = positions_resp.data or []

    candidates_resp = supabase.table('candidates') \
        .select('*,positions(name)') \
        .eq('department', department) \
        .execute()
    candidates = candidates_resp.data or []

    return render_template('admin_manage_candidates.html',
                           positions=positions,
                           candidates=candidates)


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
            'image': image_path
        }).eq('id', id).execute()
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

    # Send approval email
    send_approval_email(user['email'], user.get('first_name', ''))

    supabase.table('pending_users').delete().eq('id', user_id).execute()
    return redirect(url_for('manage_students'))


@app.route('/reject_user/<int:user_id>', methods=['POST'])
def reject_user(user_id):
    user = supabase.table('pending_users').select('*').eq(
        'id', user_id).single().execute().data
    if user:
        # Send rejection email
        send_rejection_email(user['email'], user.get('first_name', ''))
    supabase.table('pending_users').delete().eq('id', user_id).execute()
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
    current_deadline = None

    # Handle POST (save new deadline)
    if request.method == 'POST':
        new_deadline_str = request.form.get('voting_deadline')
        if new_deadline_str:
            try:
                # Parse as naive datetime (from browser input)
                dt = datetime.strptime(new_deadline_str, "%Y-%m-%dT%H:%M")
                # Attach PH timezone
                dt = dt.replace(tzinfo=PH_TZ)
                # Save as ISO string with PH timezone info
                supabase.table('settings').insert({
                    'department':
                    admin_department,
                    'voting_deadline':
                    dt.isoformat()
                }).execute()
                current_deadline = dt
                message = f"Voting deadline updated for {admin_department}!"
            except Exception:
                current_deadline = None
                message = "Invalid date format."

    # Handle GET (load latest deadline)
    setting_resp = supabase.table('settings').select('*').eq(
        'department', admin_department).order('id',
                                              desc=True).limit(1).execute()
    if setting_resp.data:
        current_deadline_str = setting_resp.data[0]['voting_deadline']
        if current_deadline_str:
            try:
                dt = datetime.fromisoformat(current_deadline_str)
                # If no tzinfo, treat as PH time
                if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                    dt = dt.replace(tzinfo=PH_TZ)
                current_deadline = dt.astimezone(PH_TZ)
            except Exception:
                current_deadline = None

    return render_template('admin_manage_settings.html',
                           admin_department=admin_department,
                           current_deadline=current_deadline,
                           message=message)


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
