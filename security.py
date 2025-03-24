import base64
import logging
import pyotp
import qrcode
import io
import ipaddress
import datetime
from functools import wraps
from flask import request, redirect, url_for, flash, session, jsonify, abort
from app import db
from models import SecurityLog, IPWhitelist, IPBlacklist, User
import config

# TOTP Functions
def generate_totp_secret():
    """Generate a new TOTP secret key"""
    return pyotp.random_base32()

def get_totp_uri(username, secret, issuer):
    """Generate TOTP URI for QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret, token):
    """Verify TOTP token"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_totp_qrcode_url(uri):
    """Generate QR code for TOTP setup"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert PIL image to base64 string
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

# Security Logging
def log_security_event(event_type, user_id=None, details="", ip_address="", user_agent="", success=True):
    """Log security events to the database"""
    log_entry = SecurityLog(
        event_type=event_type,
        user_id=user_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success
    )
    
    db.session.add(log_entry)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to log security event: {str(e)}")

def get_client_info(request):
    """Get client IP and user agent from request"""
    ip_address = request.remote_addr
    user_agent = request.user_agent.string if request.user_agent else "Unknown"
    
    return {
        'ip_address': ip_address,
        'user_agent': user_agent
    }

# IP Whitelist/Blacklist Functions
def ip_is_allowed(ip_address):
    """
    Check if an IP address is allowed to access the system
    Based on whitelist/blacklist configuration
    """
    # If IP whitelist is empty, allow all IPs that are not blacklisted
    # If IP whitelist is not empty, only allow IPs in the whitelist
    
    # Check if IP is in the database blacklist
    blacklisted = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    if blacklisted:
        log_security_event(
            event_type='blacklisted_ip_access_attempt',
            details=f"Blocked access attempt from blacklisted IP: {ip_address}",
            ip_address=ip_address,
            user_agent=request.user_agent.string if request.user_agent else "Unknown",
            success=False
        )
        return False
    
    # Check if IP is in the config blacklist
    for blacklist_ip in config.IP_BLACKLIST:
        try:
            if ip_in_network(ip_address, blacklist_ip):
                log_security_event(
                    event_type='blacklisted_ip_access_attempt',
                    details=f"Blocked access attempt from blacklisted IP: {ip_address}",
                    ip_address=ip_address,
                    user_agent=request.user_agent.string if request.user_agent else "Unknown",
                    success=False
                )
                return False
        except:
            continue
    
    # Check whitelist
    whitelist_db = IPWhitelist.query.all()
    whitelist_config = config.IP_WHITELIST
    
    # If both whitelists are empty, allow the IP (as it's not blacklisted)
    if not whitelist_db and not whitelist_config:
        return True
    
    # Check if IP is in the database whitelist
    for whitelist_entry in whitelist_db:
        if ip_address == whitelist_entry.ip_address:
            return True
    
    # Check if IP is in the config whitelist
    for whitelist_ip in whitelist_config:
        try:
            if ip_in_network(ip_address, whitelist_ip):
                return True
        except:
            continue
    
    # IP is not in whitelist (and whitelist is not empty)
    log_security_event(
        event_type='unauthorized_ip_access_attempt',
        details=f"Blocked access attempt from non-whitelisted IP: {ip_address}",
        ip_address=ip_address,
        user_agent=request.user_agent.string if request.user_agent else "Unknown",
        success=False
    )
    return False

def ip_in_network(ip, network):
    """Check if an IP is in a network or matches exactly"""
    # If network contains a slash, it's a CIDR notation
    if '/' in network:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
    # Otherwise, it should be an exact match
    return ip == network

# Security Utility Functions
def check_for_suspicious_activity(user_id):
    """Check for suspicious activity patterns"""
    
    user = User.query.get(user_id)
    if not user:
        return False
    
    # Check for recent failed login attempts
    recent_failed_logins = SecurityLog.query.filter_by(
        user_id=user_id,
        event_type='failed_login',
        success=False
    ).filter(
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    ).count()
    
    # Current login IP
    current_ip = request.remote_addr
    
    # Get distinct IPs used for login in the last 24 hours
    recent_ips = SecurityLog.query.filter_by(
        user_id=user_id,
        event_type='successful_login'
    ).filter(
        SecurityLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    ).with_entities(SecurityLog.ip_address).distinct().all()
    recent_ips = [ip[0] for ip in recent_ips]
    
    # Check if current IP is different from recent successful logins
    ip_mismatch = current_ip not in recent_ips and len(recent_ips) > 0
    
    # If we have multiple failed logins or IP mismatch, log it as suspicious
    if recent_failed_logins >= 3 or ip_mismatch:
        log_security_event(
            event_type='suspicious_activity_detected',
            user_id=user_id,
            details=f"Suspicious activity: Failed logins: {recent_failed_logins}, IP mismatch: {ip_mismatch}",
            ip_address=current_ip,
            user_agent=request.user_agent.string if request.user_agent else "Unknown",
            success=True
        )
        return True
    
    return False

def detect_intrusion_attempt(request):
    """Simple intrusion detection function"""
    # Check for SQL injection patterns in request parameters
    sql_patterns = [
        "1=1", "OR 1=1", "' OR '", "-- ", "/*", "*/", "UNION SELECT", 
        "DROP TABLE", "DELETE FROM", "INSERT INTO", "EXEC(", "EXECUTE("
    ]
    
    # Check query parameters
    for param, value in request.args.items():
        if isinstance(value, str):
            for pattern in sql_patterns:
                if pattern.lower() in value.lower():
                    client_info = get_client_info(request)
                    log_security_event(
                        event_type='possible_sql_injection',
                        details=f"Possible SQL injection in parameter {param}: {value}",
                        ip_address=client_info['ip_address'],
                        user_agent=client_info['user_agent'],
                        success=False
                    )
                    return True
    
    # Check form data
    if request.form:
        for param, value in request.form.items():
            if isinstance(value, str):
                for pattern in sql_patterns:
                    if pattern.lower() in value.lower():
                        client_info = get_client_info(request)
                        log_security_event(
                            event_type='possible_sql_injection',
                            details=f"Possible SQL injection in form field {param}: {value}",
                            ip_address=client_info['ip_address'],
                            user_agent=client_info['user_agent'],
                            success=False
                        )
                        return True
    
    # Check for XSS patterns
    xss_patterns = [
        "<script>", "</script>", "javascript:", "onerror=", "onload=",
        "eval(", "document.cookie", "document.write("
    ]
    
    # Check query parameters
    for param, value in request.args.items():
        if isinstance(value, str):
            for pattern in xss_patterns:
                if pattern.lower() in value.lower():
                    client_info = get_client_info(request)
                    log_security_event(
                        event_type='possible_xss_attempt',
                        details=f"Possible XSS in parameter {param}: {value}",
                        ip_address=client_info['ip_address'],
                        user_agent=client_info['user_agent'],
                        success=False
                    )
                    return True
    
    # Check form data
    if request.form:
        for param, value in request.form.items():
            if isinstance(value, str):
                for pattern in xss_patterns:
                    if pattern.lower() in value.lower():
                        client_info = get_client_info(request)
                        log_security_event(
                            event_type='possible_xss_attempt',
                            details=f"Possible XSS in form field {param}: {value}",
                            ip_address=client_info['ip_address'],
                            user_agent=client_info['user_agent'],
                            success=False
                        )
                        return True
    
    return False
