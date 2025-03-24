from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
import config

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters'),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Please enter a valid email address'),
        Length(max=120, message='Email must be less than 120 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=config.PASSWORD_MIN_LENGTH, message=f'Password must be at least {config.PASSWORD_MIN_LENGTH} characters'),
        Regexp('^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$',
               message='Password must include at least one letter, one number, and one special character')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class TOTPVerifyForm(FlaskForm):
    totp_code = StringField('Authentication Code', validators=[
        DataRequired(message='Authentication code is required'),
        Length(min=6, max=6, message='Authentication code must be 6 digits'),
        Regexp('^\d{6}$', message='Authentication code must be 6 digits')
    ])
    submit = SubmitField('Verify')

class UserManagementForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters'),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Please enter a valid email address'),
        Length(max=120, message='Email must be less than 120 characters')
    ])
    role = SelectField('Role', choices=[
        ('admin', 'Administrator'),
        ('user', 'Standard User'),
        ('readonly', 'Read-Only User')
    ], validators=[
        DataRequired(message='Role is required')
    ])
    is_active = BooleanField('Active')
    submit = SubmitField('Save')

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Current password is required')
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='New password is required'),
        Length(min=config.PASSWORD_MIN_LENGTH, message=f'Password must be at least {config.PASSWORD_MIN_LENGTH} characters'),
        Regexp('^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$',
               message='Password must include at least one letter, one number, and one special character')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your new password'),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class IPManagementForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[
        DataRequired(message='IP address is required'),
        Regexp('^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d{1,2})?$',
               message='Please enter a valid IP address (IPv4) or CIDR notation')
    ])
    description = StringField('Description', validators=[
        Length(max=255, message='Description must be less than 255 characters')
    ])
    submit = SubmitField('Add')
