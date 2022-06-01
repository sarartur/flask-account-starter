import enum

class AccountLogActions(enum.Enum):
    LOGIN_SUCCESS = dict(msg="login successful", category="success")
    LOGIN_FAILURE = dict(msg="login failure", category="warning")
    LOGOUT = dict(msg="logout", category="info")
    PASSWORD_RESET = dict(msg="password reset", category="info")
    ACCOUNT_BLOCKED = dict(msg="account blocked", category="danger")
    ACCOUNT_UNBLOCKED = dict(msg="account unblocked", category="success")
    NEW_IP_VERIFIED = dict(msg="new ip verified", category="warning")


class AccountBlockReasons(enum.Enum):
    LOGIN_ATTEMPTS_EXCEEDED = "login attempts exceeded"
