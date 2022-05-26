from ipaddress import ip_address
from authlib.jose import JsonWebToken
from datetime import datetime
from flask import (
    current_app, 
    request
)
from flask_login import (
    UserMixin,
    login_user,
    logout_user
)
from sqlalchemy import desc

from .enums import (
    AccountLogActions,
    AccountBlockReasons
)
from .. import (
    db, 
    login_manager,
    bcrypt
)
from ..core.models import BaseMixin

class UserAccount(BaseMixin, UserMixin, db.Model):
    __tablename__ = 'user_account'

    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    last_active = db.Column(db.DateTime)
    is_blocked = db.Column(db.Boolean, default=False)
    block_reason = db.Column(db.Enum(AccountBlockReasons))

    logins = db.relationship('UserAccountLog', backref='user')

    def login(self, remember):
        login_user(self, remember=remember)
        db.session.add(UserAccountLog(
            user_id=self.id,
            action=AccountLogActions.LOGIN_SUCCESS
        ))
        db.session.commit()
    
    def logout(self):
        logout_user()
        db.session.add(UserAccountLog(
            user_id=self.id,
            action=AccountLogActions.LOGOUT
        ))
        db.session.commit()

    def reg_login_failure(self):
        db.session.add(UserAccountLog(
            user_id=self.id,
            action=AccountLogActions.LOGIN_FAILURE
        ))
        db.session.commit()
        last_login_or_passwd_reset = UserAccountLog.query\
            .filter(UserAccountLog.action in [
                AccountLogActions.LOGIN_SUCCESS, 
                AccountLogActions.PASSWORD_RESET
            ])\
            .order_by(desc(UserAccountLog.timestamp))\
            .first()
        failed_attempts_since_query = UserAccountLog.query\
            .filter_by(action=AccountLogActions.LOGIN_FAILURE)
        if last_login_or_passwd_reset:
            failed_attempts_since_query = failed_attempts_since_query\
                .filter(UserAccountLog.timestamp > last_login_or_passwd_reset.timestamp)
        failed_attempts_since = failed_attempts_since_query.count()
        if failed_attempts_since >= current_app.config['LOGIN_MAX_RETIRES']:
            self.update(
                is_blocked=True,
                block_reason=AccountBlockReasons.LOGIN_ATTEMPTS_EXCEEDED
            )
            db.session.add(UserAccountLog(
                user_id=self.id,
                action=AccountLogActions.ACCOUNT_BLOCKED
            ))
        db.session.commit()

    def set_new_password(self, passwd):
        was_blocked = self.is_blocked
        self.update(
            password=bcrypt.generate_password_hash(passwd).decode('utf-8'),
            is_blocked=False,
            reason_blocked=None
        )
        db.session.add(UserAccountLog(
            user_id=self.id,
            action=AccountLogActions.PASSWORD_RESET
        ))
        if was_blocked:
            db.session.add(UserAccountLog(
                user_id=self.id,
                action=AccountLogActions.ACCOUNT_UNBLOCKED
            ))
        db.session.commit()

    def get_token(self):
        jwt = JsonWebToken(['RS256'])
        return jwt.encode(
            header={'alg': 'RS256'},
            payload={
                'user_id': self.id, 
                'exp': int((datetime.utcnow() + current_app.config['PWD_RESET_EXP']).timestamp())
            },
            key=current_app.config['JWT_PRIVATE_KEY'])

    @classmethod
    def verify_token(cls, token):
        jwt = JsonWebToken(['RS256'])
        claims = jwt.decode(token, current_app.config['JWT_PUBLIC_KEY'])
        try:
            claims.validate()
        except Exception as err:
            current_app.logger.debug(err)
            return None
        else:
            return cls.query.filter_by(id = claims['user_id']).first()

@login_manager.user_loader
def user_loader(user_id):
    return UserAccount.query.get(int(user_id))

class UserAccountLog(BaseMixin, db.Model):
    __tablename__ = 'user_accountlog'

    ip_address = db.Column(db.Text, nullable=False, default=lambda: request.remote_addr)
    action = db.Column(db.Enum(AccountLogActions))

    user_id = db.Column(db.Integer, db.ForeignKey('user_account.id'))
