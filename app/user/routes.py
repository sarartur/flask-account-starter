from flask import (
    render_template,
    redirect,
    url_for,
    flash,
    request
)
from flask_login import current_user
from sqlalchemy import desc

from . import user_bp
from .models import UserAccountLog
from .forms import VerificationForm
from .. import ( email)
from ..auth import (
    login_required,
    verification_setting_required
)

@user_bp.route('/profile')
@login_required()
def profile():
    login_records = UserAccountLog.query\
        .filter_by(user_id=current_user.id)\
        .order_by(desc(UserAccountLog.timestamp))\
        .paginate(request.args.get('page', 1, type=int), 25)
    return render_template('user/profile.html', user=current_user,
        login_records=login_records)

@user_bp.route('/profile/not-verified', methods=['GET', 'POST'])
@login_required(verified_only=False)
@verification_setting_required
def profile_not_verified():
    if current_user.is_verified:
        flash('Account already verified', 'info')
        return redirect(url_for('user.profile'))
    form = VerificationForm()
    if form.validate_on_submit():
        email.send_verification(current_user)
    return render_template('user/profile_not_verified.html', user=current_user, form=form)