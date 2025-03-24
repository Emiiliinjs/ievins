import datetime
import logging
from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify, abort
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    jwt_required, get_jwt_identity, get_jwt,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)

from app import db, bcrypt, limiter, jwt
from models import User, SecurityLog, JWTTokenBlocklist
from forms import LoginForm, RegistrationForm, TOTPVerifyForm
from security import (
    get_client_info, log_security_event, 
    verify_totp, generate_totp_qrcode_url,
    generate_totp_secret, get_totp_uri
)
import config

auth_bp = Blueprint('auth', __name__)

# JWT token management
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = JWTTokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

# Custom decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.url))
            
            user = User.query.get(session['user_id'])
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('auth.logout'))
                
            if user.role.name not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('auth.dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.url))
                
            user = User.query.get(session['user_id'])
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('auth.logout'))
                
            if not user.has_permission(permission):
                flash('You do not have permission to perform this action.', 'danger')
                return redirect(url_for('auth.dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Endpoint to display custom error page
@auth_bp.route('/error/<int:error_code>')
def error(error_code):
    return render_template('base.html', 
                           error_code=error_code, 
                           error_message="Access denied or page not found"), error_code

# Registration endpoint
@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if 'user_id' in session:
        return redirect(url_for('auth.dashboard'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return render_template('register.html', form=form)
            
        # Default role should be 'user'
        from models import Role
        role = Role.query.filter_by(name='user').first()
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        totp_secret = generate_totp_secret()
        
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role_id=role.id,
            totp_secret=totp_secret,
            totp_enabled=False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log the registration
        client_info = get_client_info(request)
        log_security_event(
            event_type='user_registration',
            user_id=new_user.id,
            details=f"New user registration: {new_user.username}",
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent'],
            success=True
        )
        
        flash('Registration successful. Please set up two-factor authentication.', 'success')
        
        # Log the user in and redirect to 2FA setup
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        session['setup_2fa'] = True
        
        return redirect(url_for('auth.setup_2fa'))
        
    return render_template('register.html', form=form)

# Login endpoint
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('auth.dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        client_info = get_client_info(request)
        
        # Check if user exists and account is not locked
        if not user or user.is_account_locked():
            error_message = 'Invalid username or password.'
            if user and user.is_account_locked():
                error_message = f'Account locked until {user.locked_until}. Too many failed login attempts.'
                
            log_security_event(
                event_type='failed_login',
                user_id=user.id if user else None,
                details=f"Failed login attempt for username: {username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False
            )
            
            flash(error_message, 'danger')
            return render_template('login.html', form=form)
            
        # Verify password
        if not bcrypt.check_password_hash(user.password_hash, password):
            # Increment failed login attempts
            user.failed_login_attempts += 1
            
            # Check if we need to lock the account
            if user.failed_login_attempts >= config.FAILED_LOGIN_ATTEMPTS:
                user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(seconds=config.LOCKOUT_TIME)
                error_message = f'Account locked until {user.locked_until}. Too many failed login attempts.'
            else:
                error_message = 'Invalid username or password.'
                
            db.session.commit()
            
            log_security_event(
                event_type='failed_login',
                user_id=user.id,
                details=f"Failed login attempt for user: {user.username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False
            )
            
            flash(error_message, 'danger')
            return render_template('login.html', form=form)
        
        # Password verified, now check if 2FA is enabled
        if user.totp_enabled:
            # Store user ID temporarily for 2FA verification
            session['temp_user_id'] = user.id
            session['temp_username'] = user.username
            
            # Redirect to 2FA verification page
            return redirect(url_for('auth.verify_2fa'))
        else:
            # If 2FA is not set up, prompt user to set it up
            session['user_id'] = user.id
            session['username'] = user.username
            session['setup_2fa'] = True
            
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            log_security_event(
                event_type='successful_login',
                user_id=user.id,
                details=f"User login: {user.username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=True
            )
            
            flash('Please set up two-factor authentication for your account.', 'warning')
            return redirect(url_for('auth.setup_2fa'))
            
    return render_template('login.html', form=form)

# 2FA verification endpoint
@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    # Check if user has initiated login
    if 'temp_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
        
    form = TOTPVerifyForm()
    
    if form.validate_on_submit():
        user = User.query.get(session['temp_user_id'])
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))
            
        totp_code = form.totp_code.data
        client_info = get_client_info(request)
        
        # Verify TOTP code
        if verify_totp(user.totp_secret, totp_code):
            # Clear temporary session data
            user_id = session.pop('temp_user_id', None)
            username = session.pop('temp_username', None)
            
            # Set proper session data
            session['user_id'] = user_id
            session['username'] = username
            
            # Reset failed login attempts and update last login
            user.failed_login_attempts = 0
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Create JWT tokens
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)
            
            # Log successful login
            log_security_event(
                event_type='successful_2fa_verification',
                user_id=user_id,
                details=f"2FA verification successful for user: {username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=True
            )
            
            flash('Login successful.', 'success')
            
            # Redirect to the original destination or dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('auth.dashboard'))
        else:
            # Log failed 2FA attempt
            log_security_event(
                event_type='failed_2fa_verification',
                user_id=user.id,
                details=f"Failed 2FA verification for user: {user.username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=False
            )
            
            flash('Invalid verification code. Please try again.', 'danger')
            
    return render_template('verify_2fa.html', form=form)

# 2FA setup endpoint
@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.logout'))
        
    # Generate TOTP setup information
    totp_uri = get_totp_uri(user.username, user.totp_secret, config.TOTP_ISSUER)
    qrcode_url = generate_totp_qrcode_url(totp_uri)
    
    form = TOTPVerifyForm()
    if form.validate_on_submit():
        totp_code = form.totp_code.data
        
        # Verify that the TOTP code is correct
        if verify_totp(user.totp_secret, totp_code):
            # Enable 2FA for the user
            user.totp_enabled = True
            db.session.commit()
            
            # Clear setup flag
            session.pop('setup_2fa', None)
            
            client_info = get_client_info(request)
            log_security_event(
                event_type='2fa_setup',
                user_id=user.id,
                details=f"2FA setup completed for user: {user.username}",
                ip_address=client_info['ip_address'],
                user_agent=client_info['user_agent'],
                success=True
            )
            
            flash('Two-factor authentication has been set up successfully.', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('setup_2fa.html', 
                           form=form, 
                           qrcode_url=qrcode_url, 
                           secret_key=user.totp_secret)

# Dashboard endpoint
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    # Check if 2FA setup is required
    if session.get('setup_2fa', False):
        flash('Please set up two-factor authentication to continue.', 'warning')
        return redirect(url_for('auth.setup_2fa'))
        
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.logout'))
        
    # Redirect admins to admin dashboard
    if user.role.name == 'admin':
        return redirect(url_for('auth.admin_dashboard'))
        
    return render_template('dashboard.html', user=user)

# Admin dashboard endpoint
@auth_bp.route('/admin')
@login_required
@role_required(['admin'])
def admin_dashboard():
    user = User.query.get(session['user_id'])
    return render_template('admin.html', user=user)

# User management endpoint
@auth_bp.route('/admin/users')
@login_required
@permission_required('manage_users')
def user_management():
    users = User.query.all()
    return render_template('user_management.html', users=users)

# IP management endpoint
@auth_bp.route('/admin/ip-management')
@login_required
@permission_required('manage_system')
def ip_management():
    from models import IPWhitelist, IPBlacklist
    whitelisted_ips = IPWhitelist.query.all()
    blacklisted_ips = IPBlacklist.query.all()
    return render_template('ip_management.html', 
                           whitelisted_ips=whitelisted_ips, 
                           blacklisted_ips=blacklisted_ips)

# Security logs endpoint
@auth_bp.route('/admin/security-logs')
@login_required
@permission_required('view_logs')
def security_logs():
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(500).all()
    return render_template('security_logs.html', logs=logs)

# Profile management endpoint
@auth_bp.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.logout'))
        
    return render_template('profile.html', user=user)

# Root route - redirect to login
@auth_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('auth.dashboard'))
    return redirect(url_for('auth.login'))

# Logout endpoint
@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    
    if user_id:
        # Log the logout event
        client_info = get_client_info(request)
        log_security_event(
            event_type='logout',
            user_id=user_id,
            details="User logged out",
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent'],
            success=True
        )
    
    # Clear session
    session.clear()
    
    # Clear JWT cookies if present
    response = redirect(url_for('auth.login'))
    unset_jwt_cookies(response)
    
    flash('You have been logged out.', 'info')
    return response
