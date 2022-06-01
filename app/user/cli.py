import click
from flask import current_app, url_for
from flask.cli import AppGroup
from sqlalchemy.exc import IntegrityError

from .models import UserAccount
from .. import bcrypt, db
from ..auth.utils import validate_password

user_cli = AppGroup("user")


@user_cli.command("create")
@click.argument("email")
@click.option("--verified", "-v", is_flag=True)
def create_user(email, verified):
    user = UserAccount.query.filter_by(email=email).first()
    if user:
        raise Exception("Email already taken")
    password = input("Enter user password: ")
    if not validate_password(password):
        continue_ = input(
            "Password does not meet security requirements. Would you like to continue? (Y/N)"
        )
        if not continue_.lower().startswith("y"):
            raise Exception("Password invalid.")
    user = UserAccount(
        email=email,
        password=bcrypt.generate_password_hash(password).decode("utf-8"),
        is_verified=verified,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        raise Exception("Could not add user.")
    else:
        current_app.logger.info("User Added!")


@user_cli.command("passwd")
@click.argument("email")
def create_user(email):
    user = UserAccount.query.filter_by(email=email).first()
    if not user:
        raise Exception("User not found")
    url = url_for("auth.password_reset", token=user.get_token(), _external=True)
    current_app.logger.info(url)
