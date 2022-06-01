from flask_wtf import FlaskForm
from wtforms import PasswordField, ValidationError, EmailField, BooleanField
from wtforms.validators import DataRequired, EqualTo

from ..user.models import UserAccount
from .utils import validate_password


class PasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )

    def validate_password(self, field):
        if not validate_password(field.data):
            raise ValidationError(
                "Password must contain at least one uppercase "
                "and one lowercase letter and be at least 9 characters long."
            )


class EmailForm(FlaskForm):
    email = EmailField("Email")


class LoginForm(EmailForm, FlaskForm):
    password = PasswordField("Password", [DataRequired()])
    remember_me = BooleanField("remember me")


class RegistrationForm(EmailForm, PasswordForm):
    def validate_email(self, field):
        if UserAccount.query.filter_by(email=field.data).first():
            raise ValidationError("Email already taken.")


class PasswordResetForm(PasswordForm):
    pass
