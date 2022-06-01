from flask import Flask

from .extensions import db, login_manager, bcrypt, mail, migrate
from . import config


def create_app():
    app = Flask(__name__)
    app.config.from_object(config)
    app.jinja_env.add_extension("jinja2.ext.do")

    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    from .core import core_bp

    app.register_blueprint(core_bp)
    from .auth import auth_bp

    app.register_blueprint(auth_bp)
    from .user import user_bp

    app.register_blueprint(user_bp)
    from .email import email_bp

    app.register_blueprint(email_bp)

    from .user.cli import user_cli

    app.cli.add_command(user_cli)

    return app
