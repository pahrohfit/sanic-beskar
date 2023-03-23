from buzz import Buzz

from sanic.exceptions import SanicException
from sanic import json
from sanic.response import JSONResponse


class BeskarError(SanicException, Buzz):
    """
    Provides a custom exception class for sanic-beskar based on py-buzz.
    `py-buzz on gitub <https://github.com/dusktreader/py-buzz>`_
    """
    status: int = 401

    def __init__(self, message: str, *args: tuple, **kwargs: dict):
        self.status: int = self.status
        self.message: str = f'{self.__class__.__name__}: {message}'
        self.extra_args: tuple = args
        self.extra_kwargs: dict = kwargs
        self.json_response: JSONResponse = json({
                                                 "error": message,
                                                 "data": self.__class__.__name__,
                                                 "status": self.status,
                                                },
                                                status=self.status)
        super().__init__(self.message, self.status)

    def __str__(self) -> str:
        return f"{super().__str__()} ({self.status})"


class MissingClaimError(BeskarError):
    """
    The token is missing a required claim
    """
    pass


class BlacklistedError(BeskarError):
    """
    The token has been blacklisted and may not be used any more
    """
    status = 403


class ExpiredAccessError(BeskarError):
    """
    The token has expired for access and must be refreshed
    """
    pass


class EarlyRefreshError(BeskarError):
    """
    The token has not yet expired for access and may not be refreshed
    """
    status = 425  # HTTP Status Code : 425 Too Early


class ExpiredRefreshError(BeskarError):
    """
    The token has expired for refresh. An entirely new token must be issued
    """
    pass


class MissingToken(BeskarError):
    """
    The header is missing the required token
    """
    pass


class InvalidTokenHeader(BeskarError):
    """
    The token contained in the header is invalid
    """
    pass


class VerifyError(InvalidTokenHeader):
    """
    The token contained in the header is invalid
    """
    pass


class InvalidUserError(BeskarError):
    """
    The user is no longer valid and is now not authorized
    """
    status = 403


class MissingRoleError(BeskarError):
    """
    The token is missing a required role
    """
    status = 403


class MissingRightError(BeskarError):
    """
    The token is missing a required right based upon role breakdown
    """
    status = 403


class MissingUserError(BeskarError):
    """
    The user could not be identified
    """
    pass


class AuthenticationError(BeskarError):
    """
    The entered user's password did not match the stored password
    """
    pass


class ClaimCollisionError(BeskarError):
    """"
    Custom claims to pack into the payload collide with reserved claims
    """
    pass


class LegacyScheme(BeskarError):
    """
    The processed hash is using an outdated scheme
    """
    pass


class InvalidResetToken(BeskarError):
    """
    The supplied registration token is invalid
    """
    pass


class InvalidRegistrationToken(BeskarError):
    """
    The supplied registration token is invalid
    """
    pass


class MisusedRegistrationToken(BeskarError):
    """
    Attempted to use a registration token for normal access
    """
    pass


class MisusedResetToken(BeskarError):
    """
    Attempted to use a password reset token for normal access
    """
    pass


class ConfigurationError(BeskarError):
    """
    There was a problem with the configuration
    """
    pass


class TOTPRequired(AuthenticationError):
    """
    The user requires TOTP authentication, per configuation
    `BESKAR_TOTP_ENFORCE` which was not performed
    by this call to `authenticate()`. A call to
    `authenticate_totp()` should be performed seperately,
    or a call to `authenticate()` again, but providing the
    users `token` value should be done.
    """
    pass
