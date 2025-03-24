import datetime
import re
import logging
from app import db
from models import User, SecurityLog, IPWhitelist, IPBlacklist

def validate_password_strength(password):
    """
    Validates password strength according to policy
    Returns (valid, message) tuple
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    
    return True, "Password meets strength requirements."

def is_valid_ip(ip):
    """
    Validates if a string is a valid IPv4 address
    """
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    
    if not match:
        return False
    
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False
    
    return True

def is_valid_cidr(cidr):
    """
    Validates if a string is a valid CIDR notation
    """
    if '/' not in cidr:
        return False
    
    ip, prefix = cidr.split('/')
    
    if not is_valid_ip(ip):
        return False
    
    try:
        prefix_int = int(prefix)
        if prefix_int < 0 or prefix_int > 32:
            return False
    except ValueError:
        return False
    
    return True

def add_to_whitelist(ip, description, added_by_id):
    """
    Add an IP address to the whitelist
    """
    if not is_valid_ip(ip) and not is_valid_cidr(ip):
        return False, "Invalid IP address format."
    
    existing = IPWhitelist.query.filter_by(ip_address=ip).first()
    if existing:
        return False, "IP address already in whitelist."
    
    entry = IPWhitelist(
        ip_address=ip,
        description=description,
        added_by=added_by_id,
        created_at=datetime.datetime.utcnow()
    )
    
    db.session.add(entry)
    try:
        db.session.commit()
        return True, "IP address added to whitelist."
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to add IP to whitelist: {str(e)}")
        return False, f"Database error: {str(e)}"

def add_to_blacklist(ip, reason, added_by_id):
    """
    Add an IP address to the blacklist
    """
    if not is_valid_ip(ip) and not is_valid_cidr(ip):
        return False, "Invalid IP address format."
    
    existing = IPBlacklist.query.filter_by(ip_address=ip).first()
    if existing:
        return False, "IP address already in blacklist."
    
    entry = IPBlacklist(
        ip_address=ip,
        reason=reason,
        added_by=added_by_id,
        created_at=datetime.datetime.utcnow()
    )
    
    db.session.add(entry)
    try:
        db.session.commit()
        return True, "IP address added to blacklist."
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to add IP to blacklist: {str(e)}")
        return False, f"Database error: {str(e)}"

def remove_from_whitelist(ip_id):
    """
    Remove an IP address from the whitelist
    """
    entry = IPWhitelist.query.get(ip_id)
    if not entry:
        return False, "IP address not found in whitelist."
    
    db.session.delete(entry)
    try:
        db.session.commit()
        return True, "IP address removed from whitelist."
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to remove IP from whitelist: {str(e)}")
        return False, f"Database error: {str(e)}"

def remove_from_blacklist(ip_id):
    """
    Remove an IP address from the blacklist
    """
    entry = IPBlacklist.query.get(ip_id)
    if not entry:
        return False, "IP address not found in blacklist."
    
    db.session.delete(entry)
    try:
        db.session.commit()
        return True, "IP address removed from blacklist."
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to remove IP from blacklist: {str(e)}")
        return False, f"Database error: {str(e)}"

def get_security_stats():
    """
    Get security statistics for dashboard
    """
    now = datetime.datetime.utcnow()
    today = datetime.datetime(now.year, now.month, now.day)
    
    # Today's login attempts
    total_logins_today = SecurityLog.query.filter(
        SecurityLog.event_type == 'successful_login',
        SecurityLog.timestamp >= today
    ).count()
    
    failed_logins_today = SecurityLog.query.filter(
        SecurityLog.event_type == 'failed_login',
        SecurityLog.timestamp >= today
    ).count()
    
    # Last 7 days login attempts
    week_ago = now - datetime.timedelta(days=7)
    total_logins_week = SecurityLog.query.filter(
        SecurityLog.event_type == 'successful_login',
        SecurityLog.timestamp >= week_ago
    ).count()
    
    failed_logins_week = SecurityLog.query.filter(
        SecurityLog.event_type == 'failed_login',
        SecurityLog.timestamp >= week_ago
    ).count()
    
    # Suspicious activity
    suspicious_activity = SecurityLog.query.filter(
        SecurityLog.event_type.in_([
            'suspicious_activity_detected',
            'possible_sql_injection',
            'possible_xss_attempt',
            'blacklisted_ip_access_attempt'
        ]),
        SecurityLog.timestamp >= week_ago
    ).count()
    
    # Active users
    active_users = User.query.filter_by(is_active=True).count()
    
    # Locked accounts
    locked_accounts = User.query.filter(
        User.locked_until != None,
        User.locked_until > now
    ).count()
    
    return {
        'total_logins_today': total_logins_today,
        'failed_logins_today': failed_logins_today,
        'total_logins_week': total_logins_week,
        'failed_logins_week': failed_logins_week,
        'suspicious_activity': suspicious_activity,
        'active_users': active_users,
        'locked_accounts': locked_accounts
    }
