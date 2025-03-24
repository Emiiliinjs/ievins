import os
import logging
import datetime
from datetime import timedelta

from flask import Flask, flash, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy.orm import DeclarativeBase
import config

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize Flask extensions
db = SQLAlchemy(model_class=Base)
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Create the app
def create_app():
    app = Flask(__name__)
    
    # Set configuration from config.py
    app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.secret_key = os.environ.get("SESSION_SECRET", config.SECRET_KEY)
    app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=config.JWT_ACCESS_TOKEN_EXPIRES)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(seconds=config.JWT_REFRESH_TOKEN_EXPIRES)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=config.SESSION_TIMEOUT)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    
    # Set security headers with Talisman
    csp = {
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', 'https://code.jquery.com', '\'unsafe-inline\''],
        'style-src': ['\'self\'', 'https://cdn.replit.com', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
        'img-src': ['\'self\'', 'data:'],
        'font-src': ['\'self\'', 'https://cdn.jsdelivr.net'],
    }
    Talisman(app, content_security_policy=csp, force_https=False)  # force_https=False for development
    
    # Configure session security
    @app.before_request
    def make_session_permanent():
        session.permanent = True
    
    # Request IP checking for blacklist/whitelist
    @app.before_request
    def check_ip_access():
        from security import ip_is_allowed
        client_ip = request.remote_addr
        
        # Skip IP check for static resources and the error page
        if request.path.startswith('/static/') or request.endpoint == 'error':
            return
            
        if not ip_is_allowed(client_ip):
            flash('Your IP address is not allowed to access this system.', 'danger')
            return redirect(url_for('auth.error', error_code=403))
    
    # Register blueprints
    from auth import auth_bp
    from api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Add utility functions to Jinja environment
    @app.context_processor
    def utility_processor():
        return {
            'now': datetime.datetime.utcnow
        }
    
    # Create database tables
    with app.app_context():
        import models  # Import models to ensure they're registered
        db.create_all()
        
        # Create default admin if no users exist
        from models import User, Role
        if not User.query.first():
            # Create roles
            admin_role = Role.query.filter_by(name='admin').first()
            if not admin_role:
                admin_role = Role(name='admin', description='Administrator with all permissions')
                db.session.add(admin_role)
                
            user_role = Role.query.filter_by(name='user').first() 
            if not user_role:
                user_role = Role(name='user', description='Standard user')
                db.session.add(user_role)
                
            readonly_role = Role.query.filter_by(name='readonly').first()
            if not readonly_role:
                readonly_role = Role(name='readonly', description='Read-only access')
                db.session.add(readonly_role)
                
            db.session.commit()
            
            # Create default admin user
            from security import generate_totp_secret
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=bcrypt.generate_password_hash('Admin123!').decode('utf-8'),
                is_active=True,
                role_id=admin_role.id,
                totp_secret=generate_totp_secret(),
                totp_enabled=False
            )
            db.session.add(admin_user)
            db.session.commit()
            logging.info("Created default admin user")
    
    return app

# Create the application instance
app = create_app()
