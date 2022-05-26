from flask import (
    current_app,
    flash,
    request
)
from flask_login import (
    login_required as _login_required,
    logout_user,
    login_user
)
from sqlalchemy import desc

from .. import (
    bcrypt,
    db
)
from ..user.models import UserAccountLog
from ..user.enums import (
    AccountLogActions, 
    AccountBlockReasons
)
from .. import email

def handle_login(user, passwd, remember):
    if not user or not bcrypt.check_password_hash(user.password, passwd):
        _handle_invalid_credentials(user)
        flash('Invalid Credentials', 'danger')
        return 1
    if user.is_blocked:
        flash(f'Your account has been blocked. Reason: {user.block_reason.value}', 'danger')
        return 1
    if request.remote_addr not in user.verified_ips \
        and current_app.config['LOGIN_NEW_IP_VERIFY']:
        flash('Login from new IP Address detected.', 'warning')
        email.send_login_confirmation(user, ip_address=request.remote_addr)
        return 1
    _login_user(user, remember=remember)
    return 0

def _login_user(user, remember):
    login_user(user, remember=remember)
    user.add_log(AccountLogActions.LOGIN_SUCCESS)
    flash('You have been logged in!', 'success')

def _handle_invalid_credentials(user):
    user.add_log(AccountLogActions.LOGIN_FAILURE)
    last_login_or_passwd_reset = UserAccountLog.query\
        .filter_by(user_id=user.id)\
        .filter(UserAccountLog.action in [
            AccountLogActions.LOGIN_SUCCESS, 
            AccountLogActions.PASSWORD_RESET
        ])\
        .order_by(desc(UserAccountLog.timestamp))\
        .first()
    failed_attempts_since_query = UserAccountLog.query\
        .filter_by(user_id=user.id)\
        .filter_by(action=AccountLogActions.LOGIN_FAILURE)
    if last_login_or_passwd_reset:
        failed_attempts_since_query = failed_attempts_since_query\
            .filter(UserAccountLog.timestamp > last_login_or_passwd_reset.timestamp)
    failed_attempts_since = failed_attempts_since_query.count()
    if failed_attempts_since >= current_app.config['LOGIN_MAX_RETIRES']:
        user.update(
            is_blocked=True,
            block_reason=AccountBlockReasons.LOGIN_ATTEMPTS_EXCEEDED
        )
        user.add_log(AccountLogActions.ACCOUNT_BLOCKED)
    db.session.commit()
    
def handle_logout(user):
    user.add_log(AccountLogActions.LOGOUT)
    logout_user()
    flash('You have been logged out!', 'info')

def handle_password_change(user, passwd):
    was_blocked = user.is_blocked
    user.update(
        password=bcrypt.generate_password_hash(passwd).decode('utf-8'),
        is_blocked=False,
        reason_blocked=None
    )
    user.add_log(AccountLogActions.PASSWORD_RESET, commit=False)
    if was_blocked:
        user.add_log(AccountLogActions.ACCOUNT_UNBLOCKED, commit=False)
    db.session.commit()
    flash('Password reset successfully!', 'success')

def handle_registration(user):
    user.add_log(AccountLogActions.NEW_IP_VERIFIED)
    if current_app.config['ACCOUNT_VERIFICATION']:
        email.send_verification(user)
    flash('Account created', 'success')
    
    