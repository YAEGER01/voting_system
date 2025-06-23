from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from models import db, User, Position, Candidate, Vote, Setting
import os
import re
import sys
import platform
from datetime import datetime

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.template_filter('nl2br')
def nl2br_filter(s):
    return s.replace('\n', '<br>') if s else ''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        school_id = request.form.get('school_id', '').strip()
        password = request.form.get('password', '')

        if not school_id or not password:
            flash("Please fill in all fields.", 'danger')
        else:
            user = User.query.filter_by(school_id=school_id).first()
            if user and check_password_hash(user.password_hash, password):
                session['school_id'] = user.school_id
                session['role'] = user.role
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash("Invalid School ID or Password.", 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        school_id = request.form.get('school-id', '').strip()
        course = request.form.get('course', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        first_name = request.form.get('first-name', '').strip()
        last_name = request.form.get('last-name', '').strip()
        phone = request.form.get('phone', '').strip()
        front_file = request.files.get('school-id-front')
        back_file = request.files.get('school-id-back')

        if not all([school_id, course, email, password, confirm_password, first_name, last_name, phone, front_file, back_file]):
            flash("All fields are required.", 'danger')
            return redirect(request.url)

        if not allowed_file(front_file.filename) or not allowed_file(back_file.filename):
            flash('Only image files are allowed for ID photos.', 'danger')
            return redirect(request.url)

        if len(front_file.read()) > MAX_FILE_SIZE or len(back_file.read()) > MAX_FILE_SIZE:
            flash('Each ID image must be less than 5MB.', 'danger')
            return redirect(request.url)
        front_file.seek(0)
        back_file.seek(0)

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(request.url)

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$', password):
            flash('Password must have uppercase, lowercase, digit, and special character.', 'danger')
            return redirect(request.url)

        # Check duplicates
        if User.query.filter_by(school_id=school_id).first():
            flash('School ID already registered.', 'danger')
            return redirect(request.url)
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(request.url)
        if User.query.filter_by(phone=phone).first():
            flash('Phone number already in use.', 'danger')
            return redirect(request.url)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        front_filename = secure_filename(f"{school_id}_front_{front_file.filename}")
        back_filename = secure_filename(f"{school_id}_back_{back_file.filename}")
        front_path = os.path.join(UPLOAD_FOLDER, front_filename)
        back_path = os.path.join(UPLOAD_FOLDER, back_filename)

        front_file.save(front_path)
        back_file.save(back_path)

        hashed_password = generate_password_hash(password)
        new_user = User(
            school_id=school_id,
            course=course,
            email=email,
            password_hash=hashed_password,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            id_photo_front=front_path,
            id_photo_back=back_path,
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Successfully Registered!", "success")
        return redirect(url_for('register'))

    return render_template('register.html')

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
        else:
            email = f"{school_id}@admin.local"
            existing = User.query.filter(
                (User.school_id == school_id) | (User.email == email)
            ).first()
            if existing:
                flash("School ID or generated email already exists.", 'danger')
            else:
                password_hash = generate_password_hash(password)
                new_admin = User(
                    school_id=school_id,
                    course=course,
                    email=email,
                    password_hash=password_hash,
                    first_name=first_name,
                    last_name=last_name,
                    role='admin'
                )
                db.session.add(new_admin)
                db.session.commit()
                flash("Admin registered successfully!", "success")
        return redirect(url_for('register_admin'))

    return render_template('register_admin.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'school_id' not in session:
        return redirect(url_for('login'))

    school_id = session['school_id']
    user = User.query.filter_by(school_id=school_id).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    dept_logo = DEPARTMENT_LOGOS.get(user.course.upper())
    now = datetime.now()
    voting_deadline = None
    voting_closed = False

    # Get voting deadline for department
    setting = Setting.query.filter_by(department=user.course).order_by(Setting.id.desc()).first()
    if setting:
        voting_deadline = setting.voting_deadline
        voting_closed = now > voting_deadline

    # Voting logic
    if request.method == 'POST' and not voting_closed:
        for position_id, candidate_id in request.form.items():
            if position_id.isdigit() and candidate_id.isdigit():
                existing_vote = Vote.query.filter_by(student_id=school_id, position_id=int(position_id)).first()
                if not existing_vote:
                    vote = Vote(
                        student_id=school_id,
                        position_id=int(position_id),
                        candidate_id=int(candidate_id),
                        department=user.course
                    )
                    db.session.add(vote)
        db.session.commit()
        flash('Your vote has been submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Get positions for department
    positions = Position.query.filter_by(department=user.course).all()
    voted_positions = [
        v.position_id for v in Vote.query.filter_by(student_id=school_id).all()
    ]

    # For each position, get candidates
    candidates_per_position = {}
    for pos in positions:
        candidates_per_position[pos.id] = Candidate.query.filter_by(position_id=pos.id).all()

    return render_template(
        'dashboard.html',
        user=user,
        dept_logo=dept_logo,
        voting_deadline=voting_deadline,
        now=now,
        voting_closed=voting_closed,
        positions=positions,
        voted_positions=voted_positions,
        candidates_per_position=candidates_per_position
    )

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    admin = User.query.filter_by(school_id=school_id).first()
    return render_template('admin_dashboard.html', admin=admin)

@app.route('/manage_poll', methods=['GET', 'POST'])
def manage_poll():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin = User.query.filter_by(school_id=session['school_id']).first()
    admin_department = admin.course if admin else ''
    message = ""

    # Handle adding a new position
    if request.method == 'POST' and 'position_name' in request.form:
        position_name = request.form.get('position_name', '').strip()
        if position_name:
            new_position = Position(name=position_name, department=admin_department)
            db.session.add(new_position)
            db.session.commit()
            message = "Position added successfully!"

    # Handle adding a new candidate
    if request.method == 'POST' and 'candidate_name' in request.form and 'position_id' in request.form:
        candidate_name = request.form.get('candidate_name', '').strip()
        position_id = request.form.get('position_id')
        campaign_message = request.form.get('campaign_message', '').strip()
        image_path = ''

        # Handle image upload
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
                filename = secure_filename(f"{int(Position.query.count())}_{file.filename}")
                image_path = f"uploads/candidates/{filename}"  # always forward slashes
                full_save_path = os.path.join(app.root_path, 'static', 'uploads', 'candidates', filename)
                file.save(full_save_path)
        if candidate_name and position_id and not message:
            new_candidate = Candidate(
                position_id=position_id,
                name=candidate_name,
                image=image_path,
                campaign_message=campaign_message
            )
            db.session.add(new_candidate)
            db.session.commit()
            message = "Candidate added successfully!"

    # Get all positions and candidates for this department
    positions = Position.query.filter_by(department=admin_department).all()
    candidates_per_position = {}
    for pos in positions:
        candidates_per_position[pos.id] = Candidate.query.filter_by(position_id=pos.id).all()

    return render_template(
        'manage_poll.html',
        admin_department=admin_department,
        message=message,
        positions=positions,
        candidates_per_position=candidates_per_position
    )

@app.route('/manage_candidates', methods=['GET', 'POST'])
def manage_candidates():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    # Handle add candidate
    if request.method == 'POST' and 'add_candidate' in request.form:
        name = request.form.get('name', '').strip()
        position_id = request.form.get('position_id')
        campaign_message = request.form.get('campaign_message', '').strip()
        image_path = None

        file = request.files.get('image')
        if file and file.filename:
            os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
            filename = secure_filename(f"{int(Position.query.count())}_{file.filename}")
            image_path = f"uploads/candidates/{filename}"  # always forward slashes
            full_save_path = os.path.join(app.root_path, 'static', 'uploads', 'candidates', filename)
            print("Attempting to save file to:", full_save_path)  # Debug print
            try:
                file.save(full_save_path)
                print("File saved successfully.")
            except Exception as e:
                print("File save error:", e)
                flash("Error saving file: " + str(e), "danger")

        new_candidate = Candidate(
            position_id=position_id,
            name=name,
            image=image_path,
            campaign_message=campaign_message
        )
        db.session.add(new_candidate)
        db.session.commit()
        flash("Candidate added successfully!", "success")
        return redirect(url_for('manage_candidates'))

    # Fetch all positions for dropdown
    positions = Position.query.order_by(Position.name.asc()).all()

    # Fetch all candidates with position names
    candidates = db.session.query(
        Candidate, Position.name.label('position_name')
    ).join(Position, Candidate.position_id == Position.id).order_by(Position.name, Candidate.name).all()

    return render_template(
        'manage_candidates.html',
        positions=positions,
        candidates=candidates
    )

@app.route('/candidates')
def candidates():
    if 'school_id' not in session:
        flash("You must be logged in to view candidates.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    user = User.query.filter_by(school_id=school_id).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    department = user.course
    positions = Position.query.filter_by(department=department).order_by(Position.name.asc()).all()

    # For each position, get candidates
    positions_with_candidates = []
    for pos in positions:
        candidates = Candidate.query.filter_by(position_id=pos.id).all()
        positions_with_candidates.append({
            'position': pos,
            'candidates': candidates
        })

    return render_template(
        'candidates.html',
        department=department,
        positions_with_candidates=positions_with_candidates
    )

@app.route('/candidate/<int:id>')
def candidate_details(id):
    if 'school_id' not in session:
        flash("You must be logged in to view candidate details.", "danger")
        return redirect(url_for('login'))

    candidate = db.session.query(
        Candidate, Position.name.label('position_name')
    ).join(Position, Candidate.position_id == Position.id).filter(Candidate.id == id).first()

    if not candidate:
        flash("Candidate not found.", "danger")
        return redirect(url_for('candidates'))

    cand, position_name = candidate[0], candidate[1]
    return render_template(
        'candidate_details.html',
        candidate=cand,
        position_name=position_name
    )

@app.route('/view_results')
def view_results():
    if 'school_id' not in session:
        flash("You must be logged in to view results.", "danger")
        return redirect(url_for('login'))

    school_id = session['school_id']
    user = User.query.filter_by(school_id=school_id).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    department = user.course

    # Get all positions for this department
    positions = Position.query.filter_by(department=department).order_by(Position.name.asc()).all()

    # For each position, get candidates and their vote counts
    results = []
    for pos in positions:
        candidates = Candidate.query.filter_by(position_id=pos.id).all()
        candidate_list = []
        for cand in candidates:
            vote_count = Vote.query.filter_by(candidate_id=cand.id, position_id=pos.id).count()
            candidate_list.append({
                'id': cand.id,
                'name': cand.name,
                'image': cand.image,
                'vote_count': vote_count
            })
        results.append({
            'position': pos,
            'candidates': candidate_list
        })

    return render_template(
        'view_results.html',
        department=department,
        results=results
    )

@app.route('/delete_candidate/<int:id>')
def delete_candidate(id):
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    candidate = Candidate.query.get(id)
    if candidate:
        # Delete candidate image file if it exists
        if candidate.image:
            image_path = os.path.join('static', candidate.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        db.session.delete(candidate)
        db.session.commit()
        flash("Candidate deleted successfully!", "success")
    else:
        flash("Candidate not found.", "danger")
    return redirect(url_for('manage_candidates'))

@app.route('/edit_candidate/<int:id>', methods=['GET', 'POST'])
def edit_candidate(id):
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    candidate = Candidate.query.get_or_404(id)
    positions = Position.query.order_by(Position.name.asc()).all()

    if request.method == 'POST':
        candidate.name = request.form.get('name', '').strip()
        candidate.position_id = request.form.get('position_id')
        candidate.campaign_message = request.form.get('campaign_message', '').strip()

        file = request.files.get('image')
        if file and file.filename:
            # Delete old image if exists
            if candidate.image:
                old_path = os.path.join('static', candidate.image)
                if os.path.exists(old_path):
                    os.remove(old_path)
            os.makedirs(CANDIDATE_UPLOAD_FOLDER, exist_ok=True)
            filename = secure_filename(f"{int(Position.query.count())}_{file.filename}")
            image_path = f"uploads/candidates/{filename}"  # always forward slashes
            full_save_path = os.path.join(app.root_path, 'static', 'uploads', 'candidates', filename)
            file.save(full_save_path)
            candidate.image = image_path

        db.session.commit()
        flash("Candidate updated successfully!", "success")
        return redirect(url_for('manage_candidates'))

    return render_template('edit_candidate.html', candidate=candidate, positions=positions)

@app.route('/manage_settings', methods=['GET', 'POST'])
def manage_settings():
    if 'school_id' not in session or session.get('role') != 'admin':
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for('login'))

    admin = User.query.filter_by(school_id=session['school_id']).first()
    admin_department = admin.course if admin else ''
    message = ""
    current_deadline = None

    # Get current deadline for this department
    setting = Setting.query.filter_by(department=admin_department).order_by(Setting.id.desc()).first()
    if setting:
        current_deadline = setting.voting_deadline

    # Handle form submission
    if request.method == 'POST':
        new_deadline_str = request.form.get('voting_deadline')
        if new_deadline_str:
            try:
                new_deadline = datetime.strptime(new_deadline_str, "%Y-%m-%dT%H:%M")
                new_setting = Setting(department=admin_department, voting_deadline=new_deadline)
                db.session.add(new_setting)
                db.session.commit()
                current_deadline = new_deadline
                message = f"Voting deadline updated for {admin_department}!"
            except ValueError:
                message = "Invalid date format."

    return render_template(
        'manage_settings.html',
        admin_department=admin_department,
        current_deadline=current_deadline,
        message=message
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/db-test')
def db_test():
    result = db.session.execute("SELECT COUNT(*) FROM users")
    count = result.fetchone()[0]
    return f"Total users: {count}"

# For development/debug only
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
    app.run(debug=True)