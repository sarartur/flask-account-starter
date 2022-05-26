from flask import (
    Blueprint,
    current_app,
    redirect,
    url_for,
)
from flask_login import (
    login_required as _login_required,
    current_user,
)
import functools

auth_bp = Blueprint('auth', __name__, template_folder='templates')

def login_required(verified_only=True):
    def layer(func):
        @_login_required
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_verified \
                and current_app.config['ACCOUNT_VERIFICATION'] \
                and verified_only:
                return redirect(url_for('user.profile_not_verified'))
            return func(*args, **kwargs)
        return wrapper
    return layer

def verification_setting_required(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not current_app.config['ACCOUNT_VERIFICATION']:
            return redirect(url_for('auth.login'))
        return func(*args, **kwargs)
    return wrapper

from .routes import auth_bp