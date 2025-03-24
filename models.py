import datetime
from app import db
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255))
    
    # Relationship
    users = relationship('User', back_populates='role')
    
    def __repr__(self):
        return f'<Role {self.name}>'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime)
    role_id = Column(Integer, ForeignKey('roles.id'))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    totp_secret = Column(String(32))
    totp_enabled = Column(Boolean, default=False)
    
    # Relationships
    role = relationship('Role', back_populates='users')
    security_logs = relationship('SecurityLog', back_populates='user')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def has_permission(self, permission):
        from config import ROLES
        if self.role and self.role.name in ROLES:
            return permission in ROLES[self.role.name]
        return False
    
    def is_account_locked(self):
        if self.locked_until and self.locked_until > datetime.datetime.utcnow():
            return True
        return False

class IPWhitelist(db.Model):
    __tablename__ = 'ip_whitelist'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False)  # Support for IPv6
    description = Column(String(255))
    added_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<IPWhitelist {self.ip_address}>'

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False)  # Support for IPv6
    reason = Column(String(255))
    added_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<IPBlacklist {self.ip_address}>'

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    details = Column(Text)
    success = Column(Boolean, default=True)
    
    # Relationships
    user = relationship('User', back_populates='security_logs')
    
    def __repr__(self):
        return f'<SecurityLog {self.event_type} @ {self.timestamp}>'

class JWTTokenBlocklist(db.Model):
    __tablename__ = 'jwt_token_blocklist'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False, index=True)
    token_type = Column(String(10), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    revoked_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires = Column(DateTime, nullable=False)
    
    def __repr__(self):
        return f'<JWTTokenBlocklist {self.jti}>'
