from wtforms import ValidationError
import re


def validate_password(string_):
    if (
        len(string_) < 8
        or not re.search("[0-9]", string_)
        or not re.search("[a-z]", string_)
        or not re.search("[A-Z]", string_)
    ):
        return False
    return True
