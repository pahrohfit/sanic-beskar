from pendulum import Duration, duration
import enum
from os.path import dirname, abspath


DEFAULT_TOKEN_PLACES: list = ["header", "cookie"]
DEFAULT_TOKEN_COOKIE_NAME: str = "access_token"
DEFAULT_TOKEN_HEADER_NAME: str = "Authorization"
DEFAULT_TOKEN_HEADER_TYPE: str = "Bearer"
DEFAULT_TOKEN_ACCESS_LIFESPAN: Duration = duration(minutes=15)
DEFAULT_TOKEN_REFRESH_LIFESPAN: Duration = duration(days=30)
DEFAULT_TOKEN_RESET_LIFESPAN: Duration = duration(minutes=10)
DEFAULT_JWT_ALGORITHM: str = "HS256"
DEFAULT_JWT_ALLOWED_ALGORITHMS: list = ["HS256"]

DEFAULT_ROLES_DISABLED: bool = False

DEFAULT_USER_CLASS_VALIDATION_METHOD: str = "is_valid"

DEFAULT_PASSWORD_POLICY: dict = {
    'length': 8,
    'allow_reuse': False,
    'attempt_lockout': 6,
}

DEFAULT_CONFIRMATION_TEMPLATE = (
    "{}/sanic_beskar/templates/registration_email.html".format(
        dirname(dirname(abspath(__file__))),
    )
)

DEFAULT_CONFIRMATION_SENDER: str = "you@whatever.com"
DEFAULT_CONFIRMATION_SUBJECT: str = "Please confirm your registration"

DEFAULT_RESET_TEMPLATE = "{}/sanic_beskar/templates/{}".format(
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
DEFAULT_TOTP_SECRETS_TYPE: str = ''
DEFAULT_TOTP_SECRETS_DATA: str = ''

DEFAULT_TOKEN_PROVIDER: str = 'jwt'  # jwt|paseto
DEFAULT_PASETO_VERSION: int = 4  # 1|2|3|4

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
VITAM_AETERNUM: Duration = duration(days=1000000)


class AccessType(enum.Enum):
    access: str = "ACCESS"
    refresh: str = "REFRESH"
    register: str = "REGISTER"
    reset: str = "RESET"
