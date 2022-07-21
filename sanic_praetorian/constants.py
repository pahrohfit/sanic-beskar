import pendulum
import enum
from os.path import dirname, abspath


DEFAULT_JWT_PLACES: list = ["header", "cookie"]
DEFAULT_JWT_COOKIE_NAME: str = "access_token"
DEFAULT_JWT_HEADER_NAME: str = "Authorization"
DEFAULT_JWT_HEADER_TYPE: str = "Bearer"
DEFAULT_JWT_ACCESS_LIFESPAN: pendulum = pendulum.duration(minutes=15)
DEFAULT_JWT_REFRESH_LIFESPAN: pendulum = pendulum.duration(days=30)
DEFAULT_JWT_RESET_LIFESPAN: pendulum = pendulum.duration(minutes=10)
DEFAULT_JWT_ALGORITHM: str = "HS256"
DEFAULT_JWT_ALLOWED_ALGORITHMS: list = ["HS256"]

DEFAULT_ROLES_DISABLED: bool = False

DEFAULT_USER_CLASS_VALIDATION_METHOD: str = "is_valid"

DEFAULT_CONFIRMATION_TEMPLATE = (
    "{}/sanic_praetorian/templates/registration_email.html".format(
        dirname(dirname(abspath(__file__))),
    )
)

DEFAULT_CONFIRMATION_SENDER: str = "you@whatever.com"
DEFAULT_CONFIRMATION_SUBJECT: str = "Please confirm your registration"

DEFAULT_RESET_TEMPLATE = "{}/sanic_praetorian/templates/{}".format(
    dirname(dirname(abspath(__file__))),
    "reset_email.html",
)

DEFAULT_RESET_SENDER: str = "you@whatever.com"
DEFAULT_RESET_SUBJECT: str = "Password Reset Requested"

DEFAULT_HASH_AUTOUPDATE: bool = False
DEFAULT_HASH_AUTOTEST: bool = False
DEFAULT_HASH_SCHEME: str = "pbkdf2_sha512"
DEFAULT_HASH_ALLOWED_SCHEMES: list = [
    "pbkdf2_sha512",
    "sha256_crypt",
    "sha512_crypt",
    "bcrypt",
    "argon2",
    "bcrypt_sha256",
]
DEFAULT_HASH_DEPRECATED_SCHEMES: list = []

DEFAULT_TOTP_ENFORCE: bool = True
DEFAULT_TOTP_SECRETS_TYPE: str = None
DEFAULT_TOTP_SECRETS_DATA: str = None

REFRESH_EXPIRATION_CLAIM: str = "rf_exp"
IS_REGISTRATION_TOKEN_CLAIM: str = "is_ert"
IS_RESET_TOKEN_CLAIM: str = "is_prt"
RESERVED_CLAIMS = {
    "iat",
    "exp",
    "jti",
    "id",
    "rls",
    REFRESH_EXPIRATION_CLAIM,
    IS_REGISTRATION_TOKEN_CLAIM,
    IS_RESET_TOKEN_CLAIM,
}

# 1M days seems reasonable. If this code is being used in 3000 years...welp
VITAM_AETERNUM: pendulum = pendulum.Duration(days=1000000)


class AccessType(enum.Enum):
    access: str = "ACCESS"
    refresh: str = "REFRESH"
    register: str = "REGISTER"
    reset: str = "RESET"
