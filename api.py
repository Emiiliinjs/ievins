import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, abort, g
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token
)

from app import db, jwt, limiter
from models import User, SecurityLog, JWTTokenBlocklist
from security import log_security_event, get_client_info, detect_intrusion_attempt

api_bp = Blueprint('api', __name__)

# Middleware to check for intrusion attempts
@api_bp.before_request
def check_intrusion():
    if detect_intrusion_attempt(request):
        return jsonify({"error": "Request denied", "message": "Security violation detected"}), 403

# Custom decorators for API
def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized", "message": "Missing or invalid token"}), 401
        
        # Extract token from header
        token = auth_header.split('Bearer ')[1]
        
        # Validate token (this would normally be done by the JWT middleware)
        # but we're showing the concept of Zero Trust where we validate everything
        # at each step
        try:
            # This is simplified; in a real scenario you'd decode and verify the JWT
            user_id = get_jwt_identity()
            if not user_id:
                return jsonify({"error": "Unauthorized", "message": "Invalid token"}), 401
                
            # Store user ID in request context
            g.user_id = user_id
            
            # Check if user exists and is active
            user = User.query.get(user_id)
            if not user or not user.is_active:
                return jsonify({"error": "Unauthorized", "message": "User not found or inactive"}), 401
                
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": "Unauthorized", "message": str(e)}), 401
            
    return decorated_function

def api_role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({"error": "Unauthorized", "message": "User not found"}), 401
                
            if user.role.name not in roles:
                return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def api_permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({"error": "Unauthorized", "message": "User not found"}), 401
                
            if not user.has_permission(permission):
                return jsonify({"error": "Forbidden", "message": f"Missing permission: {permission}"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Endpoint for token refresh
@api_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "User not found or inactive"}), 401
        
    # Create new access token
    access_token = create_access_token(identity=user_id)
    
    client_info = get_client_info(request)
    log_security_event(
        event_type='token_refresh',
        user_id=user_id,
        details=f"Token refreshed for user: {user.username}",
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        success=True
    )
    
    return jsonify(access_token=access_token)

# Endpoint for token revocation
@api_bp.route('/revoke', methods=['POST'])
@jwt_required()
def revoke_token():
    user_id = get_jwt_identity()
    jti = get_jwt()["jti"]
    
    # Get token expiration
    token_exp = get_jwt()["exp"]
    expires = datetime.datetime.fromtimestamp(token_exp)
    
    # Add token to blocklist
    revoked_token = JWTTokenBlocklist(
        jti=jti,
        token_type="access",
        user_id=user_id,
        expires=expires
    )
    
    db.session.add(revoked_token)
    db.session.commit()
    
    client_info = get_client_info(request)
    log_security_event(
        event_type='token_revoked',
        user_id=user_id,
        details=f"Token revoked for user ID: {user_id}",
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        success=True
    )
    
    return jsonify({"message": "Token revoked successfully"})

# Example protected user profile endpoint
@api_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    client_info = get_client_info(request)
    log_security_event(
        event_type='profile_access',
        user_id=user_id,
        details=f"User {user.username} accessed profile via API",
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        success=True
    )
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.name,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "two_factor_enabled": user.totp_enabled
    })

# Example protected admin endpoint
@api_bp.route('/users', methods=['GET'])
@jwt_required()
@api_role_required(['admin'])
@api_permission_required('manage_users')
@limiter.limit("30 per minute")
def get_users():
    users = User.query.all()
    
    user_id = get_jwt_identity()
    client_info = get_client_info(request)
    log_security_event(
        event_type='user_list_access',
        user_id=user_id,
        details=f"Admin accessed user list via API",
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        success=True
    )
    
    return jsonify({
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.name,
                "active": user.is_active,
                "two_factor_enabled": user.totp_enabled
            } for user in users
        ]
    })

# Example security logs endpoint (with pagination)
@api_bp.route('/security-logs', methods=['GET'])
@jwt_required()
@api_permission_required('view_logs')
def get_security_logs():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)  # Limit to max 100 per page
    
    # Get logs with pagination
    logs_query = SecurityLog.query.order_by(SecurityLog.timestamp.desc())
    logs_paginated = logs_query.paginate(page=page, per_page=per_page)
    
    user_id = get_jwt_identity()
    client_info = get_client_info(request)
    log_security_event(
        event_type='security_logs_access',
        user_id=user_id,
        details=f"User accessed security logs via API",
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        success=True
    )
    
    return jsonify({
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "event_type": log.event_type,
                "user_id": log.user_id,
                "ip_address": log.ip_address,
                "details": log.details,
                "success": log.success
            } for log in logs_paginated.items
        ],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": logs_paginated.pages,
            "total_items": logs_paginated.total
        }
    })
