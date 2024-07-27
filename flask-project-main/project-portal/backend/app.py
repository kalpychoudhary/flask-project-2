from flask import Flask, request, redirect, url_for, flash, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///requests.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Google OAuth configuration
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    redirect_to='google_login'
)
app.register_blueprint(google_bp, url_prefix='/google_login')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=True)  # Nullable for OAuth users
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(150), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)  # New field to check if user is admin


class ProjectRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    entry_number = db.Column(db.String(20), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    additional_remarks = db.Column(db.Text)
    urgency = db.Column(db.String(20), nullable=False)
    estimated_duration = db.Column(db.Integer, nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/student')
@login_required
def student():
    return render_template('student.html')

@app.route('/professor')
@login_required
def professor():
    return render_template('professor.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('student'))  # Redirect to student dashboard after login
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('professor'))
        else:
            flash('Admin Login Unsuccessful. Please check email and password', 'danger')
    return render_template('admin_login.html')


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        is_admin = True
        existing_admin = User.query.filter_by(is_admin=True).first()
        if existing_admin:
            flash('Admin already registered!', 'warning')
            return redirect(url_for('admin_register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = User(email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(admin)
        db.session.commit()
        flash('Admin registered successfully! You can now log in.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin_register.html')


# @app.route('/google_login')
# def google_login():
#     if not google.authorized:
#         return redirect(url_for('google.login'))
#     resp = google.get('/oauth2/v1/userinfo')
#     assert resp.ok, resp.text
#     user_info = resp.json()
#     email = user_info['email']
#     user = User.query.filter_by(email=email).first()
#     if not user:
#         user = User(email=email, oauth_provider='google', oauth_id=user_info['id'])
#         db.session.add(user)
#         db.session.commit()
#     login_user(user)
#     return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/requests', methods=['GET'])
@login_required
def handle_requests():
    requests = ProjectRequest.query.all()
    requests_list = [
        {
            'student_name': r.student_name,
            'entry_number': r.entry_number,
            'request_type': r.request_type,
            'description': r.description,
            'submission_date': r.submission_date.strftime('%Y-%m-%d %H:%M:%S'),
            'additional_remarks': r.additional_remarks or 'None',
            'urgency': r.urgency,
            'estimated_duration': r.estimated_duration
        }
        for r in requests
    ]
    return jsonify(requests_list)

@app.route('/requests', methods=['POST'])
@login_required
def add_request():
    data = request.json
    new_request = ProjectRequest(
        student_name=data['student_name'],
        entry_number=data['entry_number'],
        request_type=data['request_type'],
        description=data['description'],
        additional_remarks=data.get('additional_remarks'),
        urgency=data['urgency'],
        estimated_duration=data['estimated_duration']
    )
    db.session.add(new_request)
    db.session.commit()
    return jsonify({'message': 'Request added successfully!'}), 201

if __name__ == '__main__':
    app.run(debug=True)
