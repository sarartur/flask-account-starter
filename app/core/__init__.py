from datetime import datetime
from flask import (
    Blueprint,
    current_app
)
from flask_login import current_user
import logging
from uuid import uuid4

from .. import (
    login_manager, 
    db
)
from ..config import Environments
from ..auth.handlers import logout_user

APP_NAME = 'App'

core_bp = Blueprint('core', __name__, template_folder='templates')

@core_bp.app_context_processor
def context_processor():
    return dict(
        get_uuid=lambda : str(uuid4()),
        app_name=APP_NAME
    )

@core_bp.before_app_first_request
def before_app_first_request():
    if current_app.config['ENV'] == Environments.DEVELOPMENT:
        current_app.logger.setLevel(logging.DEBUG)

    from ..user.models import UserAccount
    login_manager.user_loader(lambda user_id: UserAccount.query.get(int(user_id)))

@core_bp.before_app_request
def before_app_request():
    if current_user.is_authenticated:
        if current_user.is_blocked:
            logout_user(current_user)
        current_user.last_active = datetime.utcnow()
        db.session.commit()

from .routes import core_bp