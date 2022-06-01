from flask import Blueprint

user_bp = Blueprint("user", __name__, template_folder="templates")

from .routes import user_bp
