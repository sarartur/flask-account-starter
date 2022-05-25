from flask import (
    Blueprint, 
    flash,
    render_template
)
from flask_mail import Message

from .. import mail

email_bp = Blueprint('email', __name__, template_folder='templates')

def send_password_reset(user, with_flash=True):
    msg = Message(
            subject='Password Reset',
            html=render_template('email/password_reset.html', user=user),
            recipients=[user.email],
    )
    mail.send(msg)
    if with_flash:
        flash(f'Reset link sent to {user.email}', 'info')

def send_verification(user, with_flash=True):
    msg = Message(
        subject='Verify Account',
        html=render_template('email/account_verification.html', user=user),
        recipients=[user.email]
    )
    mail.send(msg)
    if with_flash:
        flash(f'Verification email sent to {user.email}', 'info')