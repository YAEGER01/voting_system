from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase_client import supabase
import os
import re
import sys
import platform
from datetime import datetime, timedelta
import hashlib
import uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret")

UPLOAD_FOLDER = os.path.join('static', 'uploads', 'school_ids')
CANDIDATE_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'candidates')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

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
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash("Invalid School ID or Password.", 'danger')

    return render_template('login2.html')


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

        flash("Successfully Registered!", "success")
        return redirect(url_for('register'))

    return render_template('register2.html')


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

        short_uuid = str(uuid.uuid4())[:8]  # ✅ Only 8 characters
        fake_phone = f"admin-{short_uuid}"  # ✅ Result is like "admin-9f2a6b1c"

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
    now = datetime.now()
    voting_deadline = None
    voting_closed = False

    setting_resp = supabase.table('settings').select('*').eq(
        'department',
        user.get('department',
                 user.get('course', ''))).order('id',
                                                desc=True).limit(1).execute()
    if setting_resp.data:
        voting_deadline_str = setting_resp.data[0]['voting_deadline']
        voting_deadline = datetime.fromisoformat(voting_deadline_str)
        voting_closed = now > voting_deadline

    if request.method == 'POST' and not voting_closed:
        for position_id, candidate_id in request.form.items():
            if position_id.isdigit() and candidate_id.isdigit():
                vote_resp = supabase.table('votes').select('*').eq(
                    'student_id', school_id).eq('position_id',
                                                int(position_id)).execute()
                if not vote_resp.data:
                    supabase.table('votes').insert({
                        'student_id':
                        school_id,
                        'position_id':
                        int(position_id),
                        'candidate_id':
                        int(candidate_id),
                        'department':
                        user.get('department', user.get('course', ''))
                    }).execute()
        flash('Your vote has been submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    positions_resp = supabase.table('positions').select('*').eq(
        'department', user.get('department', user.get('course',
                                                      ''))).execute()
    positions = positions_resp.data if positions_resp.data else []
    voted_positions_resp = supabase.table('votes').select('position_id').eq(
        'student_id', school_id).execute()
    voted_positions = [v['position_id'] for v in voted_positions_resp.data
                       ] if voted_positions_resp.data else []

    candidates_per_position = {}
    for pos in positions:
        cands_resp = supabase.table('candidates').select('*').eq(
            'position_id', pos['id']).execute()
        candidates_per_position[
            pos['id']] = cands_resp.data if cands_resp.data else []

    return render_template('dashboard.html',
                           user=user,
                           dept_logo=dept_logo,
                           voting_deadline=voting_deadline.isoformat()
                           if voting_deadline else None,
                           now=now,
                           voting_closed=voting_closed,
                           positions=positions,
                           voted_positions=voted_positions,
                           candidates_per_position=candidates_per_position)


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
        for cand in candidates:
            votes_resp = supabase.table('votes').select('id').eq(
                'candidate_id', cand['id']).eq('position_id',
                                               pos['id']).execute()
            vote_count = len(votes_resp.data) if votes_resp.data else 0
            candidate_list.append({
                'id': cand['id'],
                'name': cand['name'],
                'image': cand['image'],
                'vote_count': vote_count
            })
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

    log_resp = supabase.table("receipt_access_logs") \
        .select("*") \
        .eq("school_id", school_id) \
        .eq("status", "active") \
        .order("viewed_at", desc=True) \
        .limit(1) \
        .execute()

    log = log_resp.data[0] if log_resp.data else None

    if not log:
        view_time = now.isoformat()
        expiry_time = (now + timedelta(minutes=5)).isoformat()
        supabase.table("receipt_access_logs").insert({
            "school_id": school_id,
            "viewed_at": view_time,
            "expired_at": expiry_time,
            "status": "active"
        }).execute()
    else:
        expiry_time = datetime.fromisoformat(log['expired_at'])
        if now > expiry_time:
            supabase.table("receipt_access_logs") \
                .update({"status": "expired"}) \
                .eq("id", log['id']) \
                .execute()
            return "<h1>Receipt viewing time expired.</h1>"

    votes_resp = supabase.table("votes") \
        .select("position_id, candidate_id") \
        .eq("student_id", school_id) \
        .execute()
    votes = votes_resp.data
    hashed_votes = [
        hashlib.sha256(f"{school_id}:{v['position_id']}:{v['candidate_id']}".
                       encode()).hexdigest() for v in votes
    ]

    users_resp = supabase.table("user").select("school_id").execute()
    users = users_resp.data
    hashed_users = [
        hashlib.sha256(u['school_id'].encode()).hexdigest() for u in users
    ]

    return render_template(
        "vote_receipt.html",
        hashed_votes=hashed_votes,
        hashed_users=hashed_users,
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
                campaign_message
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
            'position_id':
            int(position_id),
            'name':
            name,
            'image':
            image_path,
            'campaign_message':
            campaign_message
        }).execute()
        flash("Candidate added successfully!", "success")
        return redirect(url_for('manage_candidates'))

    positions_resp = supabase.table('positions').select('*').order(
        'name', desc=False).execute()
    positions = positions_resp.data if positions_resp.data else []

    candidates_resp = supabase.table('candidates').select(
        '*,positions(name)').execute()
    candidates = candidates_resp.data if candidates_resp.data else []

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

    supabase.table('pending_users').delete().eq('id', user_id).execute()
    return redirect(url_for('manage_students'))


@app.route('/reject_user/<int:user_id>', methods=['POST'])
def reject_user(user_id):
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

    setting_resp = supabase.table('settings').select('*').eq(
        'department', admin_department).order('id',
                                              desc=True).limit(1).execute()
    if setting_resp.data:
        current_deadline = setting_resp.data[0]['voting_deadline']

    if request.method == 'POST':
        new_deadline_str = request.form.get('voting_deadline')
        if new_deadline_str:
            supabase.table('settings').insert({
                'department':
                admin_department,
                'voting_deadline':
                new_deadline_str
            }).execute()
            current_deadline = new_deadline_str
            message = f"Voting deadline updated for {admin_department}!"

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
