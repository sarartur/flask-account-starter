from os import curdir
from flask import (
    current_app,
    render_template, 
    redirect,
    url_for,
    flash,
)
from flask_login import (
    current_user,
)
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from . import (
    auth_bp,
    verification_setting_required,
    login_required,
    handlers
)
from .forms import (
    LoginForm,
    RegistrationForm,
    EmailForm,
    PasswordForm
)
from .. import (
    db,
    bcrypt,
    email
)
from ..user.models import UserAccount
from ..user.enums import AccountLogActions

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('core.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = UserAccount.query\
            .filter(func.lower(UserAccount.email) == func.lower(form.email.data))\
            .first()
        err = handlers.handle_login(user, form.password.data, form.remember_me.data)
        if not err:
            return redirect(url_for('core.home'))
    return render_template('auth/login.html', form=form)

@auth_bp.route('/login/verify-ip/<string:token>')
def ip_verify(token):
    user = UserAccount.verify_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
    user.add_log(AccountLogActions.NEW_IP_VERIFIED)
    flash('IP Address verified, you can now login.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('core.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = UserAccount(
            password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            email=form.email.data
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            flash('An error has occurred, please try again.', 'danger')
        else:
            handlers.handle_registration(user)
            return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth_bp.route('/password-reset/request', methods=['GET', 'POST'])
@verification_setting_required
def password_reset_request():
    form = EmailForm()
    if form.validate_on_submit():
        user = UserAccount.query\
            .filter_by(email=form.email.data)\
            .first()
        if user:
            email.send_password_reset(user, with_flash=False)
        flash(f'Reset link sent to {form.email.data}', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/password_reset_request.html', form=form)

@auth_bp.route('/password-reset/<string:token>', methods=['GET', 'POST'])
@verification_setting_required
def password_reset(token):
    redirect_route = url_for('user.profile') if current_user.is_authenticated \
        else url_for('auth.login')
    user = UserAccount.verify_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(redirect_route)
    form = PasswordForm()
    if form.validate_on_submit():
        handlers.handle_password_change(user, form.password.data)
        return redirect(redirect_route)
    return render_template('auth/password_reset.html', user=user, form=form)

@auth_bp.route('/user/verify/<string:token>')
@verification_setting_required
def user_verify(token):
    redirect_route = url_for('user.profile') if current_user.is_authenticated \
        else url_for('auth.login')
    user = UserAccount.verify_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
    elif user.is_verified:
        flash('Account already verified.', 'info')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Account verified.', 'success')
    return redirect(redirect_route)

@auth_bp.route('/logout')
@login_required(verified_only=False)
def logout():
    handlers.handle_logout(current_user)
    return redirect(url_for('auth.login'))
