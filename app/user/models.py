from authlib.jose import JsonWebToken
from datetime import datetime
from flask import current_app, request
from flask_login import UserMixin
from sqlalchemy import and_

from .enums import AccountLogActions, AccountBlockReasons
from .. import (
    db,
    login_manager,
)
from ..core.models import BaseMixin


class UserAccount(BaseMixin, UserMixin, db.Model):
    __tablename__ = "user_account"

    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    last_active = db.Column(db.DateTime)
    is_blocked = db.Column(db.Boolean, default=False)
    block_reason = db.Column(db.Enum(AccountBlockReasons))

    logs = db.relationship("UserAccountLog", backref="user")

    def add_log(self, action, ip_address=None, commit=True):
        db.session.add(
            UserAccountLog(
                user_id=self.id,
                action=action,
                ip_address=ip_address or request.remote_addr,
            )
        )
        if commit:
            db.session.commit()

    @property
    def logins(self):
        return [
            log
            for log in self.logs
            if log.action.name == AccountLogActions.LOGIN_SUCCESS.name
        ]

    @property
    def last_login(self):
        return self.logins[0]

    @property
    def verified_ips(self):
        return [
            log.ip_address
            for log in self.logs
            if log.action.name == AccountLogActions.NEW_IP_VERIFIED.name
        ]

    def get_token(self):
        jwt = JsonWebToken(["RS256"])
        return jwt.encode(
            header={"alg": "RS256"},
            payload={
                "user_id": self.id,
                "exp": int(
                    (
                        datetime.utcnow() + current_app.config["PWD_RESET_EXP"]
                    ).timestamp()
                ),
            },
            key=current_app.config["JWT_PRIVATE_KEY"],
        )

    @classmethod
    def verify_token(cls, token):
        jwt = JsonWebToken(["RS256"])
        claims = jwt.decode(token, current_app.config["JWT_PUBLIC_KEY"])
        try:
            claims.validate()
        except Exception as err:
            current_app.logger.debug(err)
            return None
        else:
            return cls.query.filter_by(id=claims["user_id"]).first()


@login_manager.user_loader
def user_loader(user_id):
    return UserAccount.query.get(int(user_id))


class UserAccountLog(BaseMixin, db.Model):
    __tablename__ = "user_accountlog"

    ip_address = db.Column(db.Text, nullable=False, default=lambda: request.remote_addr)
    action = db.Column(db.Enum(AccountLogActions))

    user_id = db.Column(db.Integer, db.ForeignKey("user_account.id"))
