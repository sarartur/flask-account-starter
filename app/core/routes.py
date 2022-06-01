from flask import redirect, url_for

from . import core_bp
from ..auth import login_required


@core_bp.route("/")
@core_bp.route("/home")
@login_required()
def home():
    return redirect(url_for("user.profile"))
