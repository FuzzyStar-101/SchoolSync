import os
import re
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Index, or_, and_, func
import cloudinary
import cloudinary.uploader

# Socket.IO with auto-detection
try:
    import eventlet
    eventlet.monkey_patch()
    from flask_socketio import SocketIO, emit, join_room, leave_room
    ASYNC_MODE = 'eventlet'
except ImportError:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    ASYNC_MODE = 'threading'

# Sentry for error tracking
try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

# Data processing
import pandas as pd
from io import BytesIO
import base64

# Initialize Flask app
app = Flask(__name__)

# Load configuration
app.config.from_object('config.Config')

# Initialize Cloudinary if credentials available
if app.config.get('CLOUDINARY_CLOUD_NAME'):
    cloudinary.config(
        cloud_name=app.config['CLOUDINARY_CLOUD_NAME'],
        api_key=app.config['CLOUDINARY_API_KEY'],
        api_secret=app.config['CLOUDINARY_API_SECRET']
    )

# Initialize Sentry
if SENTRY_AVAILABLE and app.config.get('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=app.config['SENTRY_DSN'],
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0
    )

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# Configure session
app.config['SESSION_SQLALCHEMY'] = db
sess = Session(app)

# Initialize Socket.IO
socketio = SocketIO(
    app,
    async_mode=ASYNC_MODE,
    cors_allowed_origins="*",
    manage_session=False,
    message_queue=app.config.get('SOCKETIO_MESSAGE_QUEUE')
)

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler(
    'logs/schoolsync.log',
    maxBytes=10240000,
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
app.logger.addHandler(file_handler)
app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
app.logger.info(f'SchoolSync startup - Async mode: {ASYNC_MODE}')

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.String(20), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), nullable=False, index=True)
    class_name = db.Column(db.String(20))
    subjects = db.Column(db.Text)
    avatar_type = db.Column(db.String(20), default='initial')
    avatar_data = db.Column(db.Text)
    first_login = db.Column(db.Boolean, default=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    grades = db.relationship('Grade', backref='student', lazy='dynamic', cascade='all, delete-orphan')
    tasks = db.relationship('Task', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    task_lists = db.relationship('TaskList', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='sender', lazy='dynamic', cascade='all, delete-orphan')
    teacher_subjects = db.relationship('TeacherSubject', backref='teacher', lazy='dynamic', cascade='all, delete-orphan')

class Homework(db.Model):
    __tablename__ = 'homework'
    
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date_given = db.Column(db.Date, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    class_name = db.Column(db.String(20), nullable=False, index=True)
    created_by = db.Column(db.String(20), db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Grade(db.Model):
    __tablename__ = 'grades'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False, index=True)
    subject = db.Column(db.String(100), nullable=False)
    test_type = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Float, nullable=False)
    max_score = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Schedule(db.Model):
    __tablename__ = 'schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(20), nullable=False, index=True)
    day = db.Column(db.String(20), nullable=False)
    period = db.Column(db.Integer, nullable=False)
    subject = db.Column(db.String(100))
    teacher_id = db.Column(db.String(20), db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_schedule_lookup', 'class_name', 'day', 'period'),
    )

class TaskList(db.Model):
    __tablename__ = 'task_lists'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), default='blue')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    tasks = db.relationship('Task', backref='task_list', lazy='dynamic', cascade='all, delete-orphan')

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('task_lists.id'), nullable=False)
    user_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False, index=True)
    text = db.Column(db.String(500), nullable=False)
    notes = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatRoom(db.Model):
    __tablename__ = 'chat_rooms'
    
    room_id = db.Column(db.String(50), primary_key=True)
    room_name = db.Column(db.String(200))
    room_type = db.Column(db.String(20), nullable=False)
    members = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(20), db.ForeignKey('users.user_id'))
    last_message = db.Column(db.Text)
    last_message_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages = db.relationship('Message', backref='room', lazy='dynamic', cascade='all, delete-orphan')

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False)
    room_id = db.Column(db.String(50), db.ForeignKey('chat_rooms.room_id'), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False)

class Subject(db.Model):
    __tablename__ = 'subjects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    section = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TeacherSubject(db.Model):
    __tablename__ = 'teacher_subjects'
    
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== UTILITY FUNCTIONS ====================

def sanitize_input(text):
    """Remove potentially dangerous characters"""
    if not text:
        return text
    text = re.sub(r'[<>"\']', '', str(text))
    return text.strip()

def upload_to_cloudinary(file_data, folder="avatars"):
    """Upload file to Cloudinary"""
    if not app.config.get('CLOUDINARY_CLOUD_NAME'):
        return None
    try:
        result = cloudinary.uploader.upload(file_data, folder=folder)
        return result['secure_url']
    except Exception as e:
        app.logger.error(f"Cloudinary upload error: {e}")
        return None

def generate_user_id(role):
    """Generate next available user ID"""
    prefix_map = {
        'student': 'S',
        'teacher': 'T',
        'admin': 'A',
        'superadmin': 'SA'
    }
    prefix = prefix_map.get(role, 'U')
    
    # Get last user with this prefix
    last_user = User.query.filter(User.user_id.like(f'{prefix}%')).order_by(User.user_id.desc()).first()
    
    if last_user:
        try:
            last_num = int(last_user.user_id.replace(prefix, ''))
            new_num = last_num + 1
        except:
            new_num = 1
    else:
        new_num = 1
    
    return f"{prefix}{new_num:03d}"

def generate_username(name):
    """Generate username from name"""
    # Remove special characters and spaces
    username = re.sub(r'[^a-zA-Z0-9]', '', name.lower())
    
    # Check if username exists
    base_username = username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    
    return username

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            if session.get('role') not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('login.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f'Rate limit exceeded: {request.remote_addr}')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    return jsonify({'error': 'Too many requests'}), 429

# ==================== AUTHENTICATION ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('account'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_post():
    data = request.get_json()
    username = sanitize_input(data.get('username'))
    password = data.get('password')
    is_admin = data.get('isAdmin', False)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403
    
    # Check admin portal access
    if is_admin and user.role not in ['admin', 'superadmin']:
        return jsonify({'error': 'Access denied'}), 403
    elif not is_admin and user.role in ['admin', 'superadmin']:
        return jsonify({'error': 'Please use admin portal'}), 403
    
    # Set session
    session.permanent = True
    session['user_id'] = user.user_id
    session['username'] = user.username
    session['name'] = user.name
    session['role'] = user.role
    session['class_name'] = user.class_name
    
    app.logger.info(f'User logged in: {user.username} ({user.role})')
    
    return jsonify({
        'success': True,
        'first_login': user.first_login,
        'redirect': url_for('account')
    })

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    app.logger.info(f'User logged out: {user_id}')
    return redirect(url_for('login'))

# ==================== CSRF TOKEN ====================

@app.route('/api/csrf-token')
@login_required
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})

# ==================== ACCOUNT PAGES ====================

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/schedule')
@login_required
def schedule():
    return render_template('schedule.html')

@app.route('/calendar')
@login_required
@role_required('student')
def calendar():
    return render_template('calendar.html')

@app.route('/homework')
@login_required
def homework():
    return render_template('homework.html')

@app.route('/grades')
@login_required
def grades():
    return render_template('grades.html')

@app.route('/tasks')
@login_required
def tasks():
    return render_template('tasks.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

# ==================== ADMIN PAGES ====================

@app.route('/accounts-mgmt')
@login_required
@role_required('admin', 'superadmin')
def accounts_mgmt():
    return render_template('accounts_mgmt.html')

@app.route('/data-import')
@login_required
@role_required('admin', 'superadmin')
def data_import():
    return render_template('data_import.html')

@app.route('/timetable-editor')
@login_required
@role_required('admin', 'superadmin')
def timetable_editor():
    return render_template('timetable_editor.html')

@app.route('/monitor-chats')
@login_required
@role_required('superadmin')
def monitor_chats():
    return render_template('monitor_chats.html')

@app.route('/experimental')
@login_required
@role_required('admin', 'superadmin')
def experimental():
    return render_template('experimental.html')

# ==================== ACCOUNT API ====================

@app.route('/api/account')
@login_required
@limiter.limit("30 per minute")
def get_account():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Update first_login flag
    if user.first_login:
        user.first_login = False
        db.session.commit()
    
    return jsonify({
        'user_id': user.user_id,
        'username': user.username,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'role': user.role,
        'class_name': user.class_name,
        'subjects': user.subjects,
        'avatar_type': user.avatar_type,
        'avatar_data': user.avatar_data
    })

@app.route('/api/profile')
@login_required
@limiter.limit("20 per minute")
def get_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'name': user.name,
        'username': user.username,
        'avatar_type': user.avatar_type,
        'avatar_data': user.avatar_data
    })

@app.route('/api/profile', methods=['PUT'])
@login_required
@limiter.limit("20 per minute")
def update_profile():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update name
    if 'name' in data:
        user.name = sanitize_input(data['name'])
        session['name'] = user.name
    
    # Update username
    if 'username' in data:
        new_username = sanitize_input(data['username'])
        if new_username != user.username:
            # Check if username already exists
            if User.query.filter_by(username=new_username).first():
                return jsonify({'error': 'Username already taken'}), 400
            user.username = new_username
            session['username'] = new_username
    
    # Update avatar
    if 'avatar_type' in data and 'avatar_data' in data:
        avatar_type = data['avatar_type']
        avatar_data = data['avatar_data']
        
        if avatar_type == 'uploaded' and avatar_data.startswith('data:image'):
            # Try to upload to Cloudinary
            cloud_url = upload_to_cloudinary(avatar_data)
            if cloud_url:
                avatar_data = cloud_url
        
        user.avatar_type = avatar_type
        user.avatar_data = sanitize_input(avatar_data)
    
    db.session.commit()
    app.logger.info(f'Profile updated: {user.user_id}')
    
    return jsonify({'success': True})

@app.route('/api/change-password', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def change_password():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    if not current_password or not new_password:
        return jsonify({'error': 'All fields required'}), 400
    
    if not check_password_hash(user.password_hash, current_password):
        return jsonify({'error': 'Current password incorrect'}), 401
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    user.password_hash = generate_password_hash(new_password)
    user.last_password_change = datetime.utcnow()
    db.session.commit()
    
    app.logger.info(f'Password changed: {user.user_id}')
    
    # Clear session to force re-login
    session.clear()
    
    return jsonify({'success': True})

# ==================== TASKS API ====================

@app.route('/api/task-lists')
@login_required
@limiter.limit("60 per minute")
def get_task_lists():
    lists = TaskList.query.filter_by(user_id=session['user_id']).all()
    
    result = []
    for task_list in lists:
        tasks = Task.query.filter_by(list_id=task_list.id).order_by(Task.created_at).all()
        result.append({
            'id': task_list.id,
            'name': task_list.name,
            'color': task_list.color,
            'tasks': [{
                'id': task.id,
                'text': task.text,
                'notes': task.notes,
                'completed': task.completed,
                'created_at': task.created_at.isoformat()
            } for task in tasks]
        })
    
    return jsonify(result)

@app.route('/api/task-lists', methods=['POST'])
@login_required
def create_task_list():
    data = request.get_json()
    name = sanitize_input(data.get('name'))
    color = sanitize_input(data.get('color', 'blue'))
    
    if not name:
        return jsonify({'error': 'Name required'}), 400
    
    task_list = TaskList(
        user_id=session['user_id'],
        name=name,
        color=color
    )
    db.session.add(task_list)
    db.session.commit()
    
    return jsonify({
        'id': task_list.id,
        'name': task_list.name,
        'color': task_list.color,
        'tasks': []
    })

@app.route('/api/task-lists', methods=['DELETE'])
@login_required
def delete_task_list():
    list_id = request.args.get('id', type=int)
    task_list = TaskList.query.filter_by(id=list_id, user_id=session['user_id']).first()
    
    if not task_list:
        return jsonify({'error': 'List not found'}), 404
    
    db.session.delete(task_list)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.get_json()
    list_id = data.get('list_id')
    text = sanitize_input(data.get('text'))
    notes = sanitize_input(data.get('notes', ''))
    
    if not list_id or not text:
        return jsonify({'error': 'List ID and text required'}), 400
    
    # Verify list belongs to user
    task_list = TaskList.query.filter_by(id=list_id, user_id=session['user_id']).first()
    if not task_list:
        return jsonify({'error': 'List not found'}), 404
    
    task = Task(
        list_id=list_id,
        user_id=session['user_id'],
        text=text,
        notes=notes
    )
    db.session.add(task)
    db.session.commit()
    
    return jsonify({
        'id': task.id,
        'text': task.text,
        'notes': task.notes,
        'completed': task.completed,
        'created_at': task.created_at.isoformat()
    })

@app.route('/api/tasks', methods=['PUT'])
@login_required
def update_task():
    data = request.get_json()
    task_id = data.get('id')
    
    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if 'text' in data:
        task.text = sanitize_input(data['text'])
    if 'notes' in data:
        task.notes = sanitize_input(data['notes'])
    if 'completed' in data:
        task.completed = data['completed']
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/tasks', methods=['DELETE'])
@login_required
def delete_task():
    task_id = request.args.get('id', type=int)
    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    db.session.delete(task)
    db.session.commit()
    
    return jsonify({'success': True})

# Continue in next part...
# ==================== SCHEDULE API ====================

@app.route('/api/schedule')
@login_required
@limiter.limit("60 per minute")
def get_schedule():
    class_name = request.args.get('class') or session.get('class_name')
    
    if not class_name:
        return jsonify({'error': 'Class name required'}), 400
    
    schedules = Schedule.query.filter_by(class_name=class_name).all()
    
    result = {}
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    
    for day in days:
        result[day] = {}
        for period in range(1, 9):
            result[day][str(period)] = {'subject': '', 'teacher': ''}
    
    for schedule in schedules:
        if schedule.day in result and str(schedule.period) in result[schedule.day]:
            teacher_name = ''
            if schedule.teacher_id:
                teacher = User.query.get(schedule.teacher_id)
                if teacher:
                    teacher_name = teacher.name
            
            result[schedule.day][str(schedule.period)] = {
                'subject': schedule.subject or '',
                'teacher': teacher_name
            }
    
    return jsonify(result)

@app.route('/api/admin/schedule')
@login_required
@role_required('admin', 'superadmin')
@limiter.limit("30 per minute")
def get_admin_schedule():
    class_name = request.args.get('class')
    
    if not class_name:
        return jsonify({'error': 'Class name required'}), 400
    
    schedules = Schedule.query.filter_by(class_name=class_name).all()
    
    result = {}
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    
    for day in days:
        result[day] = {}
        for period in range(1, 9):
            result[day][str(period)] = {'subject': '', 'teacher_id': '', 'teacher_name': ''}
    
    for schedule in schedules:
        if schedule.day in result and str(schedule.period) in result[schedule.day]:
            teacher_name = ''
            if schedule.teacher_id:
                teacher = User.query.get(schedule.teacher_id)
                if teacher:
                    teacher_name = teacher.name
            
            result[schedule.day][str(schedule.period)] = {
                'subject': schedule.subject or '',
                'teacher_id': schedule.teacher_id or '',
                'teacher_name': teacher_name
            }
    
    return jsonify(result)

@app.route('/api/admin/schedule', methods=['PUT'])
@login_required
@role_required('admin', 'superadmin')
@limiter.limit("30 per minute")
def save_schedule():
    data = request.get_json()
    class_name = sanitize_input(data.get('class'))
    schedule_data = data.get('schedule')
    
    if not class_name or not schedule_data:
        return jsonify({'error': 'Class and schedule required'}), 400
    
    # Delete existing schedule for this class
    Schedule.query.filter_by(class_name=class_name).delete()
    
    # Save new schedule
    for day, periods in schedule_data.items():
        for period, info in periods.items():
            if info.get('subject'):
                schedule = Schedule(
                    class_name=class_name,
                    day=day,
                    period=int(period),
                    subject=sanitize_input(info['subject']),
                    teacher_id=info.get('teacher_id')
                )
                db.session.add(schedule)
    
    db.session.commit()
    app.logger.info(f'Schedule saved for class: {class_name}')
    
    return jsonify({'success': True})

@app.route('/api/admin/check-conflicts', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def check_conflicts():
    data = request.get_json()
    teacher_id = data.get('teacher_id')
    day = data.get('day')
    period = data.get('period')
    current_class = data.get('current_class')
    
    if not teacher_id or not day or not period:
        return jsonify({'has_conflict': False})
    
    # Check if teacher is already assigned at this time
    conflict = Schedule.query.filter(
        Schedule.teacher_id == teacher_id,
        Schedule.day == day,
        Schedule.period == period,
        Schedule.class_name != current_class
    ).first()
    
    if conflict:
        # Find alternative periods
        alternatives = []
        for alt_period in range(1, 9):
            if alt_period != int(period):
                exists = Schedule.query.filter(
                    Schedule.teacher_id == teacher_id,
                    Schedule.day == day,
                    Schedule.period == alt_period
                ).first()
                if not exists:
                    alternatives.append(alt_period)
                    if len(alternatives) >= 3:
                        break
        
        return jsonify({
            'has_conflict': True,
            'conflicting_class': conflict.class_name,
            'alternatives': alternatives
        })
    
    return jsonify({'has_conflict': False})

# ==================== HOMEWORK API ====================

@app.route('/api/homework')
@login_required
@limiter.limit("60 per minute")
def get_homework():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    query = Homework.query
    
    # Students only see their class homework
    if session['role'] == 'student':
        query = query.filter_by(class_name=session['class_name'])
    
    homework_list = query.order_by(Homework.due_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    result = []
    for hw in homework_list.items:
        teacher_name = ''
        if hw.created_by:
            teacher = User.query.get(hw.created_by)
            if teacher:
                teacher_name = teacher.name
        
        result.append({
            'id': hw.id,
            'subject': hw.subject,
            'title': hw.title,
            'description': hw.description,
            'date_given': hw.date_given.isoformat(),
            'due_date': hw.due_date.isoformat(),
            'class_name': hw.class_name,
            'teacher': teacher_name
        })
    
    return jsonify(result)

@app.route('/api/homework', methods=['POST'])
@login_required
@role_required('teacher', 'admin', 'superadmin')
def create_homework():
    data = request.get_json()
    
    subject = sanitize_input(data.get('subject'))
    title = sanitize_input(data.get('title'))
    description = sanitize_input(data.get('description'))
    date_given = data.get('date_given')
    due_date = data.get('due_date')
    class_name = sanitize_input(data.get('class_name'))
    
    if not all([subject, title, date_given, due_date, class_name]):
        return jsonify({'error': 'All fields required'}), 400
    
    try:
        date_given_obj = datetime.strptime(date_given, '%Y-%m-%d').date()
        due_date_obj = datetime.strptime(due_date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    homework = Homework(
        subject=subject,
        title=title,
        description=description,
        date_given=date_given_obj,
        due_date=due_date_obj,
        class_name=class_name,
        created_by=session['user_id']
    )
    
    db.session.add(homework)
    db.session.commit()
    
    app.logger.info(f'Homework created: {homework.id} by {session["user_id"]}')
    
    return jsonify({
        'id': homework.id,
        'success': True
    })

@app.route('/api/homework', methods=['DELETE'])
@login_required
@role_required('teacher', 'admin', 'superadmin')
def delete_homework():
    hw_id = request.args.get('id', type=int)
    
    homework = Homework.query.get(hw_id)
    if not homework:
        return jsonify({'error': 'Homework not found'}), 404
    
    # Teachers can only delete their own homework
    if session['role'] == 'teacher' and homework.created_by != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403
    
    db.session.delete(homework)
    db.session.commit()
    
    app.logger.info(f'Homework deleted: {hw_id}')
    
    return jsonify({'success': True})

# ==================== GRADES API ====================

@app.route('/api/grades')
@login_required
@limiter.limit("60 per minute")
def get_grades():
    student_id = request.args.get('student_id')
    
    # Students can only see their own grades
    if session['role'] == 'student':
        student_id = session['user_id']
    
    if not student_id:
        return jsonify({'error': 'Student ID required'}), 400
    
    grades = Grade.query.filter_by(student_id=student_id).order_by(Grade.date.desc()).all()
    
    result = {}
    for grade in grades:
        subject = grade.subject
        if subject not in result:
            result[subject] = []
        
        result[subject].append({
            'test_type': grade.test_type,
            'score': grade.score,
            'max_score': grade.max_score,
            'percentage': round((grade.score / grade.max_score) * 100, 2),
            'date': grade.date.isoformat()
        })
    
    return jsonify(result)

@app.route('/api/grades', methods=['POST'])
@login_required
@role_required('teacher', 'admin', 'superadmin')
def create_grade():
    data = request.get_json()
    
    student_id = sanitize_input(data.get('student_id'))
    subject = sanitize_input(data.get('subject'))
    test_type = sanitize_input(data.get('test_type'))
    score = data.get('score')
    max_score = data.get('max_score')
    date = data.get('date')
    
    if not all([student_id, subject, test_type, score is not None, max_score, date]):
        return jsonify({'error': 'All fields required'}), 400
    
    try:
        score = float(score)
        max_score = float(max_score)
        date_obj = datetime.strptime(date, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid data format'}), 400
    
    grade = Grade(
        student_id=student_id,
        subject=subject,
        test_type=test_type,
        score=score,
        max_score=max_score,
        date=date_obj
    )
    
    db.session.add(grade)
    db.session.commit()
    
    app.logger.info(f'Grade added for student: {student_id}')
    
    return jsonify({'success': True})

# ==================== CHAT API ====================

@app.route('/api/chat/users')
@login_required
@limiter.limit("30 per minute")
def search_users():
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify([])
    
    # Search users excluding current user
    users = User.query.filter(
        User.user_id != session['user_id'],
        User.is_active == True,
        or_(
            User.name.ilike(f'%{query}%'),
            User.username.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    # Hide superadmin from non-superadmin users
    if session['role'] != 'superadmin':
        users = [u for u in users if u.role != 'superadmin']
    
    result = []
    for user in users:
        result.append({
            'user_id': user.user_id,
            'name': user.name,
            'username': user.username,
            'role': user.role
        })
    
    return jsonify(result)

@app.route('/api/chat/rooms')
@login_required
@limiter.limit("60 per minute")
def get_chat_rooms():
    # Get rooms where user is a member
    rooms = ChatRoom.query.filter(
        ChatRoom.members.like(f'%{session["user_id"]}%')
    ).order_by(ChatRoom.last_message_time.desc().nullslast()).all()
    
    result = []
    for room in rooms:
        member_ids = room.members.split(',')
        
        # Get member names
        members = []
        for member_id in member_ids:
            if member_id != session['user_id']:
                user = User.query.get(member_id)
                if user:
                    members.append(user.name)
        
        # For direct chats, use other person's name
        room_name = room.room_name
        if room.room_type == 'direct' and len(members) == 1:
            room_name = members[0]
        
        result.append({
            'room_id': room.room_id,
            'room_name': room_name,
            'room_type': room.room_type,
            'last_message': room.last_message,
            'last_message_time': room.last_message_time.isoformat() if room.last_message_time else None
        })
    
    return jsonify(result)

@app.route('/api/chat/rooms', methods=['POST'])
@login_required
def create_chat_room():
    data = request.get_json()
    member_ids = data.get('members', [])
    room_name = sanitize_input(data.get('room_name', ''))
    
    if not member_ids:
        return jsonify({'error': 'Members required'}), 400
    
    # Add current user to members
    if session['user_id'] not in member_ids:
        member_ids.append(session['user_id'])
    
    # Determine room type
    room_type = 'direct' if len(member_ids) == 2 else 'group'
    
    # For group chats, require a room name
    if room_type == 'group' and not room_name:
        return jsonify({'error': 'Group name required'}), 400
    
    # Check if direct chat already exists
    if room_type == 'direct':
        existing_room = ChatRoom.query.filter(
            ChatRoom.room_type == 'direct',
            or_(
                ChatRoom.members == f'{member_ids[0]},{member_ids[1]}',
                ChatRoom.members == f'{member_ids[1]},{member_ids[0]}'
            )
        ).first()
        
        if existing_room:
            return jsonify({'room_id': existing_room.room_id})
    
    # Generate room ID
    room_id = f"room_{int(datetime.utcnow().timestamp() * 1000)}"
    
    # Create room
    room = ChatRoom(
        room_id=room_id,
        room_name=room_name,
        room_type=room_type,
        members=','.join(member_ids),
        created_by=session['user_id']
    )
    
    db.session.add(room)
    db.session.commit()
    
    app.logger.info(f'Chat room created: {room_id}')
    
    return jsonify({'room_id': room_id})

@app.route('/api/chat/messages/<room_id>')
@login_required
@limiter.limit("60 per minute")
def get_messages(room_id):
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    # Verify user is member of room
    room = ChatRoom.query.get(room_id)
    if not room or session['user_id'] not in room.members.split(','):
        return jsonify({'error': 'Access denied'}), 403
    
    messages = Message.query.filter_by(room_id=room_id).order_by(
        Message.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    result = []
    for msg in messages.items:
        sender = User.query.get(msg.sender_id)
        result.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_name': sender.name if sender else 'Unknown',
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat()
        })
    
    # Reverse to show oldest first
    result.reverse()
    
    return jsonify(result)

# ==================== SOCKET.IO EVENTS ====================

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    if not room_id:
        return
    
    # Verify user is member
    room = ChatRoom.query.get(room_id)
    if not room or session.get('user_id') not in room.members.split(','):
        return
    
    join_room(room_id)
    emit('user_joined', {
        'user_id': session.get('user_id'),
        'name': session.get('name')
    }, room=room_id)

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data.get('room_id')
    if not room_id:
        return
    
    leave_room(room_id)
    emit('user_left', {
        'user_id': session.get('user_id'),
        'name': session.get('name')
    }, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data.get('room_id')
    message = sanitize_input(data.get('message', ''))
    
    if not room_id or not message:
        return
    
    # Verify user is member
    room = ChatRoom.query.get(room_id)
    if not room or session.get('user_id') not in room.members.split(','):
        return
    
    # Save message
    msg = Message(
        sender_id=session.get('user_id'),
        room_id=room_id,
        message=message
    )
    db.session.add(msg)
    
    # Update room last message
    room.last_message = message[:100]
    room.last_message_time = datetime.utcnow()
    db.session.commit()
    
    # Broadcast message
    emit('receive_message', {
        'sender_id': session.get('user_id'),
        'sender_name': session.get('name'),
        'message': message,
        'timestamp': msg.timestamp.isoformat()
    }, room=room_id)

@socketio.on('typing')
def handle_typing(data):
    room_id = data.get('room_id')
    if room_id:
        emit('user_typing', {
            'user_id': session.get('user_id'),
            'name': session.get('name')
        }, room=room_id, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    room_id = data.get('room_id')
    if room_id:
        emit('user_stop_typing', {
            'user_id': session.get('user_id')
        }, room=room_id, include_self=False)

# Continue in next part with Admin APIs...
# ==================== SUPER ADMIN API ====================

@app.route('/api/superadmin/all-chats')
@login_required
@role_required('superadmin')
def get_all_chats():
    rooms = ChatRoom.query.order_by(ChatRoom.created_at.desc()).all()
    
    result = []
    for room in rooms:
        message_count = Message.query.filter_by(room_id=room.room_id).count()
        
        result.append({
            'room_id': room.room_id,
            'room_name': room.room_name,
            'room_type': room.room_type,
            'message_count': message_count,
            'created_at': room.created_at.isoformat()
        })
    
    return jsonify(result)

@app.route('/api/superadmin/chat-messages/<room_id>')
@login_required
@role_required('superadmin')
def get_all_room_messages(room_id):
    room = ChatRoom.query.get(room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
    
    result = []
    for msg in messages:
        sender = User.query.get(msg.sender_id)
        result.append({
            'sender_name': sender.name if sender else 'Unknown',
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat()
        })
    
    return jsonify({
        'room_name': room.room_name,
        'messages': result
    })

# ==================== ADMIN ACCOUNTS API ====================

@app.route('/api/admin/accounts')
@login_required
@role_required('admin', 'superadmin')
@limiter.limit("30 per minute")
def get_accounts():
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    query = User.query
    
    # Hide superadmin from regular admins
    if session['role'] == 'admin':
        query = query.filter(User.role != 'superadmin')
    
    accounts = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    result = []
    for user in accounts.items:
        result.append({
            'user_id': user.user_id,
            'username': user.username,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'role': user.role,
            'class_name': user.class_name,
            'subjects': user.subjects,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat()
        })
    
    return jsonify(result)

@app.route('/api/admin/accounts', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def create_account():
    data = request.get_json()
    
    name = sanitize_input(data.get('name'))
    username = sanitize_input(data.get('username'))
    password = data.get('password')
    email = sanitize_input(data.get('email', ''))
    phone = sanitize_input(data.get('phone', ''))
    role = sanitize_input(data.get('role'))
    class_name = sanitize_input(data.get('class_name', ''))
    subjects = sanitize_input(data.get('subjects', ''))
    
    if not all([name, username, password, role]):
        return jsonify({'error': 'Name, username, password, and role required'}), 400
    
    if role not in ['student', 'teacher', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Validate email if provided
    if email:
        from email_validator import validate_email, EmailNotValidError
        try:
            validate_email(email)
        except EmailNotValidError:
            return jsonify({'error': 'Invalid email format'}), 400
    
    # Check if username exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    # Generate user ID
    user_id = generate_user_id(role)
    
    # Create user
    user = User(
        user_id=user_id,
        username=username,
        password_hash=generate_password_hash(password),
        name=name,
        email=email,
        phone=phone,
        role=role,
        class_name=class_name if role == 'student' else None,
        subjects=subjects if role == 'teacher' else None,
        avatar_type='initial',
        avatar_data=name[0].upper() if name else 'U'
    )
    
    db.session.add(user)
    db.session.commit()
    
    app.logger.info(f'Account created: {user_id} ({role})')
    
    return jsonify({
        'user_id': user_id,
        'success': True
    })

@app.route('/api/admin/accounts', methods=['DELETE'])
@login_required
@role_required('admin', 'superadmin')
def delete_account():
    user_id = request.args.get('id')
    
    # Prevent deletion of SA001
    if user_id == 'SA001':
        return jsonify({'error': 'Cannot delete super admin'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Regular admins cannot delete superadmins
    if session['role'] == 'admin' and user.role == 'superadmin':
        return jsonify({'error': 'Permission denied'}), 403
    
    db.session.delete(user)
    db.session.commit()
    
    app.logger.info(f'Account deleted: {user_id}')
    
    return jsonify({'success': True})

@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
@limiter.limit("10 per hour")
def reset_user_password():
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    if not user_id or not new_password:
        return jsonify({'error': 'User ID and new password required'}), 400
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Regular admins cannot reset superadmin passwords
    if session['role'] == 'admin' and user.role == 'superadmin':
        return jsonify({'error': 'Permission denied'}), 403
    
    user.password_hash = generate_password_hash(new_password)
    user.last_password_change = datetime.utcnow()
    db.session.commit()
    
    app.logger.info(f'Password reset for: {user_id}')
    
    return jsonify({'success': True})

# ==================== SUBJECTS & CLASSES API ====================

@app.route('/api/admin/subjects')
@login_required
@role_required('admin', 'superadmin')
def get_subjects():
    subjects = Subject.query.order_by(Subject.name).all()
    return jsonify([{'id': s.id, 'name': s.name, 'code': s.code} for s in subjects])

@app.route('/api/admin/subjects', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def create_subject():
    data = request.get_json()
    name = sanitize_input(data.get('name'))
    code = sanitize_input(data.get('code', ''))
    
    if not name:
        return jsonify({'error': 'Subject name required'}), 400
    
    if Subject.query.filter_by(name=name).first():
        return jsonify({'error': 'Subject already exists'}), 400
    
    subject = Subject(name=name, code=code)
    db.session.add(subject)
    db.session.commit()
    
    return jsonify({'id': subject.id, 'name': subject.name, 'code': subject.code})

@app.route('/api/admin/subjects', methods=['DELETE'])
@login_required
@role_required('admin', 'superadmin')
def delete_subject():
    name = request.args.get('name')
    subject = Subject.query.filter_by(name=name).first()
    
    if not subject:
        return jsonify({'error': 'Subject not found'}), 404
    
    db.session.delete(subject)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/admin/classes-list')
@login_required
@role_required('admin', 'superadmin')
def get_classes():
    classes = Class.query.order_by(Class.name).all()
    return jsonify([{'id': c.id, 'name': c.name, 'section': c.section} for c in classes])

@app.route('/api/admin/classes-list', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def create_class():
    data = request.get_json()
    name = sanitize_input(data.get('name'))
    section = sanitize_input(data.get('section', ''))
    
    if not name:
        return jsonify({'error': 'Class name required'}), 400
    
    if Class.query.filter_by(name=name).first():
        return jsonify({'error': 'Class already exists'}), 400
    
    class_obj = Class(name=name, section=section)
    db.session.add(class_obj)
    db.session.commit()
    
    return jsonify({'id': class_obj.id, 'name': class_obj.name, 'section': class_obj.section})

@app.route('/api/admin/classes-list', methods=['DELETE'])
@login_required
@role_required('admin', 'superadmin')
def delete_class():
    name = request.args.get('name')
    class_obj = Class.query.filter_by(name=name).first()
    
    if not class_obj:
        return jsonify({'error': 'Class not found'}), 404
    
    db.session.delete(class_obj)
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== TEACHER SUBJECTS API ====================

@app.route('/api/admin/teacher-subjects')
@login_required
@role_required('admin', 'superadmin')
def get_teacher_subjects():
    assignments = TeacherSubject.query.all()
    
    result = []
    for assignment in assignments:
        teacher = User.query.get(assignment.teacher_id)
        result.append({
            'id': assignment.id,
            'teacher_id': assignment.teacher_id,
            'teacher_name': teacher.name if teacher else 'Unknown',
            'subject': assignment.subject,
            'assigned_at': assignment.assigned_at.isoformat()
        })
    
    return jsonify(result)

@app.route('/api/admin/teacher-subjects', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def assign_teacher_subject():
    data = request.get_json()
    teacher_id = data.get('teacher_id')
    subject = sanitize_input(data.get('subject'))
    
    if not teacher_id or not subject:
        return jsonify({'error': 'Teacher and subject required'}), 400
    
    # Check if assignment exists
    existing = TeacherSubject.query.filter_by(
        teacher_id=teacher_id,
        subject=subject
    ).first()
    
    if existing:
        return jsonify({'error': 'Assignment already exists'}), 400
    
    assignment = TeacherSubject(teacher_id=teacher_id, subject=subject)
    db.session.add(assignment)
    db.session.commit()
    
    return jsonify({'id': assignment.id, 'success': True})

@app.route('/api/admin/teacher-subjects', methods=['DELETE'])
@login_required
@role_required('admin', 'superadmin')
def remove_teacher_subject():
    assignment_id = request.args.get('id', type=int)
    assignment = TeacherSubject.query.get(assignment_id)
    
    if not assignment:
        return jsonify({'error': 'Assignment not found'}), 404
    
    db.session.delete(assignment)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/admin/teachers-list')
@login_required
@role_required('admin', 'superadmin')
def get_teachers_list():
    teachers = User.query.filter_by(role='teacher').order_by(User.name).all()
    return jsonify([{
        'user_id': t.user_id,
        'name': t.name,
        'username': t.username
    } for t in teachers])

# ==================== DATA IMPORT API ====================

@app.route('/api/admin/upload', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
@limiter.limit("10 per hour")
def upload_data():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    data_type = request.form.get('dataType')
    
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Read file based on extension
        filename = file.filename.lower()
        
        if filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file)
        elif filename.endswith('.json'):
            df = pd.read_json(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        # Normalize column names
        df.columns = df.columns.str.lower().str.strip().str.replace(' ', '_')
        
        results = []
        success_count = 0
        error_count = 0
        
        # Auto-detect data type if not specified
        if not data_type or data_type == 'auto':
            if 'class_name' in df.columns or 'class' in df.columns:
                data_type = 'students'
            elif 'subject' in df.columns and 'periods_per_week' in df.columns:
                data_type = 'teacher_schedule'
            elif 'subject' in df.columns:
                data_type = 'teachers'
            else:
                data_type = 'students'
        
        # Process based on data type
        if data_type == 'students':
            results, success_count, error_count = process_student_import(df)
        elif data_type == 'teachers':
            results, success_count, error_count = process_teacher_import(df)
        elif data_type == 'teacher_schedule':
            results, success_count, error_count = process_teacher_schedule_import(df)
        else:
            return jsonify({'error': 'Invalid data type'}), 400
        
        db.session.commit()
        
        app.logger.info(f'Data import completed: {success_count} success, {error_count} errors')
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': len(df),
                'success': success_count,
                'errors': error_count
            }
        })
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Import error: {str(e)}')
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

def process_student_import(df):
    """Process student data import"""
    results = []
    success_count = 0
    error_count = 0
    
    for idx, row in df.iterrows():
        try:
            # Get student data
            name = sanitize_input(str(row.get('name', '')))
            class_name = sanitize_input(str(row.get('class_name', row.get('class', ''))))
            email = sanitize_input(str(row.get('email', '')))
            phone = sanitize_input(str(row.get('phone', '')))
            
            if not name or not class_name:
                results.append({
                    'row': idx + 1,
                    'status': 'error',
                    'message': 'Name and class are required'
                })
                error_count += 1
                continue
            
            # Auto-create class if it doesn't exist
            if not Class.query.filter_by(name=class_name).first():
                section = ''
                if len(class_name) > 1 and class_name[-1].isalpha():
                    section = class_name[-1]
                
                new_class = Class(name=class_name, section=section)
                db.session.add(new_class)
                results.append({
                    'row': idx + 1,
                    'status': 'info',
                    'message': f'Auto-created class: {class_name}'
                })
            
            # Generate username if not provided
            username = sanitize_input(str(row.get('username', '')))
            if not username:
                username = generate_username(name)
            
            # Check if username exists
            if User.query.filter_by(username=username).first():
                results.append({
                    'row': idx + 1,
                    'status': 'error',
                    'message': f'Username {username} already exists'
                })
                error_count += 1
                continue
            
            # Generate password
            password = str(row.get('password', 'student123'))
            
            # Generate user ID
            user_id = generate_user_id('student')
            
            # Create student
            student = User(
                user_id=user_id,
                username=username,
                password_hash=generate_password_hash(password),
                name=name,
                email=email,
                phone=phone,
                role='student',
                class_name=class_name,
                avatar_type='initial',
                avatar_data=name[0].upper()
            )
            
            db.session.add(student)
            
            results.append({
                'row': idx + 1,
                'status': 'success',
                'message': f'Created student: {name} ({username})'
            })
            success_count += 1
        
        except Exception as e:
            results.append({
                'row': idx + 1,
                'status': 'error',
                'message': str(e)
            })
            error_count += 1
    
    return results, success_count, error_count

def process_teacher_import(df):
    """Process teacher data import"""
    results = []
    success_count = 0
    error_count = 0
    
    for idx, row in df.iterrows():
        try:
            name = sanitize_input(str(row.get('name', '')))
            subjects = sanitize_input(str(row.get('subjects', row.get('subject', ''))))
            email = sanitize_input(str(row.get('email', '')))
            phone = sanitize_input(str(row.get('phone', '')))
            
            if not name:
                results.append({
                    'row': idx + 1,
                    'status': 'error',
                    'message': 'Name is required'
                })
                error_count += 1
                continue
            
            # Auto-create subjects
            if subjects:
                for subject in subjects.split(','):
                    subject = subject.strip()
                    if subject and not Subject.query.filter_by(name=subject).first():
                        new_subject = Subject(name=subject)
                        db.session.add(new_subject)
                        results.append({
                            'row': idx + 1,
                            'status': 'info',
                            'message': f'Auto-created subject: {subject}'
                        })
            
            username = sanitize_input(str(row.get('username', '')))
            if not username:
                username = generate_username(name)
            
            if User.query.filter_by(username=username).first():
                results.append({
                    'row': idx + 1,
                    'status': 'error',
                    'message': f'Username {username} already exists'
                })
                error_count += 1
                continue
            
            password = str(row.get('password', 'teacher123'))
            user_id = generate_user_id('teacher')
            
            teacher = User(
                user_id=user_id,
                username=username,
                password_hash=generate_password_hash(password),
                name=name,
                email=email,
                phone=phone,
                role='teacher',
                subjects=subjects,
                avatar_type='initial',
                avatar_data=name[0].upper()
            )
            
            db.session.add(teacher)
            
            # Create teacher-subject assignments
            if subjects:
                for subject in subjects.split(','):
                    subject = subject.strip()
                    if subject:
                        assignment = TeacherSubject(teacher_id=user_id, subject=subject)
                        db.session.add(assignment)
            
            results.append({
                'row': idx + 1,
                'status': 'success',
                'message': f'Created teacher: {name} ({username})'
            })
            success_count += 1
        
        except Exception as e:
            results.append({
                'row': idx + 1,
                'status': 'error',
                'message': str(e)
            })
            error_count += 1
    
    return results, success_count, error_count

def process_teacher_schedule_import(df):
    """Process teacher schedule import with auto-generation"""
    results = []
    success_count = 0
    error_count = 0
    
    # Normalize column names
    df.columns = df.columns.str.lower().str.strip().str.replace(' ', '_')
    
    for idx, row in df.iterrows():
        try:
            teacher_name = sanitize_input(str(row.get('teacher_name', '')))
            subject = sanitize_input(str(row.get('subject', '')))
            class_name = sanitize_input(str(row.get('class', row.get('classes', row.get('class_name', '')))))
            periods_per_week = int(row.get('periods_per_week', row.get('periods', 0)))
            
            if not all([teacher_name, subject, class_name, periods_per_week]):
                results.append({
                    'row': idx + 1,
                    'status': 'error',
                    'message': 'Teacher name, subject, class, and periods required'
                })
                error_count += 1
                continue
            
            # Find or create teacher
            teacher = User.query.filter(
                User.role == 'teacher',
                User.name.ilike(f'%{teacher_name}%')
            ).first()
            
            if not teacher:
                # Create new teacher
                username = generate_username(teacher_name)
                user_id = generate_user_id('teacher')
                
                teacher = User(
                    user_id=user_id,
                    username=username,
                    password_hash=generate_password_hash('teacher123'),
                    name=teacher_name,
                    role='teacher',
                    subjects=subject,
                    avatar_type='initial',
                    avatar_data=teacher_name[0].upper()
                )
                db.session.add(teacher)
                db.session.flush()
                
                results.append({
                    'row': idx + 1,
                    'status': 'info',
                    'message': f'Auto-created teacher: {teacher_name}'
                })
            
            # Auto-create class if needed
            if not Class.query.filter_by(name=class_name).first():
                section = ''
                if len(class_name) > 1 and class_name[-1].isalpha():
                    section = class_name[-1]
                
                new_class = Class(name=class_name, section=section)
                db.session.add(new_class)
                results.append({
                    'row': idx + 1,
                    'status': 'info',
                    'message': f'Auto-created class: {class_name}'
                })
            
            # Auto-create subject if needed
            if not Subject.query.filter_by(name=subject).first():
                new_subject = Subject(name=subject)
                db.session.add(new_subject)
                results.append({
                    'row': idx + 1,
                    'status': 'info',
                    'message': f'Auto-created subject: {subject}'
                })
            
            # Create teacher-subject assignment if needed
            if not TeacherSubject.query.filter_by(teacher_id=teacher.user_id, subject=subject).first():
                assignment = TeacherSubject(teacher_id=teacher.user_id, subject=subject)
                db.session.add(assignment)
            
            # Auto-distribute periods across the week
            days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
            periods_assigned = 0
            
            for day in days:
                if periods_assigned >= periods_per_week:
                    break
                
                # Find available period for this teacher on this day
                for period in range(1, 9):
                    if periods_assigned >= periods_per_week:
                        break
                    
                    # Check if teacher is free
                    conflict = Schedule.query.filter_by(
                        teacher_id=teacher.user_id,
                        day=day,
                        period=period
                    ).first()
                    
                    if not conflict:
                        # Check if slot is empty for this class
                        existing = Schedule.query.filter_by(
                            class_name=class_name,
                            day=day,
                            period=period
                        ).first()
                        
                        if not existing:
                            # Assign period
                            schedule = Schedule(
                                class_name=class_name,
                                day=day,
                                period=period,
                                subject=subject,
                                teacher_id=teacher.user_id
                            )
                            db.session.add(schedule)
                            periods_assigned += 1
            
            if periods_assigned < periods_per_week:
                results.append({
                    'row': idx + 1,
                    'status': 'warning',
                    'message': f'Only assigned {periods_assigned}/{periods_per_week} periods for {subject} in {class_name} (conflicts detected)'
                })
            else:
                results.append({
                    'row': idx + 1,
                    'status': 'success',
                    'message': f'Assigned {periods_assigned} periods for {teacher_name} - {subject} in {class_name}'
                })
            
            success_count += 1
        
        except Exception as e:
            results.append({
                'row': idx + 1,
                'status': 'error',
                'message': str(e)
            })
            error_count += 1
    
    return results, success_count, error_count

# ==================== HEALTH CHECK ====================

@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'unhealthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

# ==================== INITIALIZATION ====================

def init_db():
    """Initialize database with tables and default super admin"""
    with app.app_context():
        db.create_all()
        
        # Create super admin if doesn't exist
        if not User.query.get('SA001'):
            superadmin = User(
                user_id='SA001',
                username='superadmin',
                password_hash=generate_password_hash('superadmin123'),
                name='Super Administrator',
                email='admin@schoolsync.com',
                role='superadmin',
                avatar_type='initial',
                avatar_data='S',
                first_login=False
            )
            db.session.add(superadmin)
            db.session.commit()
            app.logger.info('Super admin created: SA001')

# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=app.config['DEBUG'])
	
	
	