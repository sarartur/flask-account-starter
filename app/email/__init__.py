from flask import Blueprint, flash, render_template
from flask_mail import Message

from .. import mail

email_bp = Blueprint("email", __name__, template_folder="templates")


def send_password_reset(user, with_flash=True):
    msg = Message(
        subject="Password Reset",
        html=render_template("email/password_reset.html", user=user),
        recipients=[user.email]
    )
    mail.send(msg)
    if with_flash:
        flash(f"Reset link sent to {user.email}", "info")


def send_verification(user, with_flash=True):
    msg = Message(
        subject="Verify Account",
        html=render_template("email/account_verification.html", user=user),
        recipients=[user.email],
    )
    mail.send(msg)
    if with_flash:
        flash(f"Account verification email sent to {user.email}", "info")


def send_login_confirmation(user, ip_address, with_flash=True):
    msg = Message(
        subject="Security Alert",
        html=render_template(
            "email/login_verification.html", user=user, ip_address=ip_address
        ),
        recipients=[user.email],
    )
    mail.send(msg)
    if with_flash:
        flash(f"Login verification email sent to {user.email}", "info")
