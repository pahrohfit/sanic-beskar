import functools
from collections.abc import Iterable
import re
import datetime as dt
from typing import Optional, Union, Any, TYPE_CHECKING
from types import SimpleNamespace

# If we are using `beanie`, we need to patch JSONEncoder to undersand its objectid
try: # pragma: no cover
    from beanie import PydanticObjectId as ObjectId
except (ImportError, ModuleNotFoundError): # pragma: no cover
    from bson.objectid import ObjectId # type: ignore

## If we are using `segno`, import for typing
if TYPE_CHECKING:
    from segno import QRCode
    from sanic_beskar import Beskar as BeskarType

import ujson
from json import JSONEncoder as json_JSONEncoder

from sanic import Sanic, Request
import pendulum

from sanic_beskar.constants import RESERVED_CLAIMS
from sanic_beskar.exceptions import (BeskarError, ConfigurationError)


class JSONEncoder(json_JSONEncoder): # pragma: no cover
    def default(self, o: Any) -> Any:
        if hasattr(o, '__json__'):
            return o.__json__()
        if isinstance(o, Iterable):
            return list(o)
        if isinstance(o, dt.datetime):
            return o.isoformat()
        if isinstance(o, ObjectId):
            return str(o)
        if hasattr(o, '__getitem__') and hasattr(o, 'keys'):
            return dict(o)
        if hasattr(o, '__dict__'):
            return {member: getattr(o, member)
                    for member in dir(o)
                    if not member.startswith('_') and
                    not hasattr(getattr(o, member), '__call__')}

        return JSONEncoder.default(self, o)


def get_request(request: Request) -> Request:
    try:
        if not request:
            return Request.get_current()
        return request
    except Exception:
        raise BeskarError("Could not identify current Sanic request")


def normalize_rbac(rbac_dump: dict) -> dict:
    """
    Normalize an RBAC dump into something usable.

    Yes, I know this will produce duplicates in the role lists of a permission,
    but its much faster than dealing with a set, so we don't care.

    Example:
        {'rolename': ['read', 'write', 'update'],}

    Produces:
        {'read': ['rolename'], 'write': ['rolename'], 'update': ['rolename']}

    Args:
        rbac_dump (dict): RBAC dump from config/storage.

    Returns:
        dict: Normalized (for our purposes) RBAC policy.
    """
    _inversed: dict = {}
    for k in rbac_dump:
        for v in rbac_dump[k]:
            _inversed.setdefault(v, []).append(k)

    return _inversed


async def is_valid_json(data: str) -> Any:
    """
    Simple helper to validate if a value is valid json data

    :param data: Data to validate for valid JSON
    :type data: str

    :returns: ``True``, ``False``
    :rtype: bool
    """
    try:
        return ujson.loads(data)
    except (ValueError, TypeError):
        return False


def duration_from_string(text: str) -> pendulum.Duration:
    """
    Parses a duration from a string. String may look like these patterns:
    * 1 Hour
    * 7 days, 45 minutes
    * 1y11d20m

    An exception will be raised if the text cannot be parsed

    :param text: String to parse for duration detail
    :type text: str

    :returns: Time Object
    :rtype: :py:mod:`pendulum`

    :raises: :py:exc:`~sanic_beskar.ConfigurationError` on bad strings
    """
    text = text.replace(' ', '')
    text = text.replace(',', '')
    text = text.lower()
    match = re.match(
        r'''
            ((?P<years>\d+)y[a-z]*)?
            ((?P<months>\d+)mo[a-z]*)?
            ((?P<days>\d+)d[a-z]*)?
            ((?P<hours>\d+)h[a-z]*)?
            ((?P<minutes>\d+)m[a-z]*)?
            ((?P<seconds>\d+)s[a-z]*)?
        ''',
        text,
        re.VERBOSE,
    )
    ConfigurationError.require_condition(
        match,
        f"Couldn't parse {text}",
    )
    parts = match.groupdict() # type: ignore
    clean = {k: int(v) for (k, v) in parts.items() if v}
    ConfigurationError.require_condition(
        clean,
        f"Couldn't parse {text}",
    )
    with ConfigurationError.handle_errors(f"Couldn't parse {text}"):
        return pendulum.duration(**clean)


@functools.lru_cache(maxsize=None)
def current_guard(ctx: Union[Sanic, SimpleNamespace, None] = None) -> 'BeskarType':
    """
    Fetches the current instance of :py:class:`~sanic_beskar.Beskar`
    that is attached to the current sanic app

    :param ctx: Application Context
    :type ctx: Optional[:py:class:`sanic.Sanic`]

    :returns: Current Beskar Guard object for this app context
    :rtype: :py:class:`~sanic_beskar.Beskar`

    :raises: :py:exc:`~sanic_beskar.BeskarError` if no guard found
    """
    if isinstance(ctx, Sanic):
        ctx = getattr(ctx, 'ctx')

    if not ctx:
        ctx = Sanic.get_app().ctx

    guard: BeskarType = ctx.extensions.get('beskar', None) # type: ignore
    BeskarError.require_condition(
        guard is not None,
        "No current guard found; Beskar must be initialized first",
    )
    return guard


def app_context_has_token_data(ctx: Optional[Sanic] = None) -> bool:
    """
    Checks if there is already token_data added to the app context

    :param ctx: Application Context
    :type ctx: Optional[Sanic]

    :returns: ``True``, ``False``
    :rtype: bool
    """
    if not ctx:
        ctx = Sanic.get_app().ctx

    return hasattr(ctx, 'token_data')


def add_token_data_to_app_context(token_data: dict) -> None:
    """
    Adds a dictionary of token data (presumably unpacked from a token) to the
    top of the sanic app's context

    :param token_data: ``dict`` of token data to add
    :type token_data: dict
    """
    ctx = Sanic.get_app().ctx
    ctx.token_data = token_data


def get_token_data_from_app_context() -> dict:
    """
    Fetches a dict of token data from the top of the sanic app's context

    :returns: Token ``dict`` found in current app context
    :rtype: dict
    :raises: :py:exc:`~sanic_beskar.BeskarError` on missing token
    """
    ctx = Sanic.get_app().ctx
    token_data = getattr(ctx, 'token_data', {})
    BeskarError.require_condition(
        token_data is not {},
        """
        No token_data found in app context.
        Make sure @auth_required decorator is specified *first* for route
        """,
    )
    return token_data


def remove_token_data_from_app_context() -> None:
    """
    Removes the dict of token data from the top of the sanic app's context
    """
    ctx = Sanic.get_app().ctx
    if app_context_has_token_data(ctx):
        del ctx.token_data


def current_user_id() -> Union[str, None]:
    """
    This method returns the user id retrieved from token data attached to
    the current sanic app's context

    :returns: ``id`` of current :py:class:`User`, if any
    :rtype: str
    :raises: :py:exc:`~sanic_beskar.BeskarError` if no user/token found
    """
    token_data = get_token_data_from_app_context()
    user_id: str = token_data.get('id', None)
    BeskarError.require_condition(
        user_id is not None,
        "Could not fetch an id for the current user",
    )
    return user_id


async def generate_totp_qr(user_totp: str) -> 'QRCode':
    """
    This is a helper utility to generate a :py:mod:`segno`
    QR code renderer, based upon a supplied `User` TOTP value.

    :param user_totp: TOTP configuration of the user
    :type user_totp: json

    :returns: ``Segno`` object based upon user's stored TOTP configuration
    :rtype: :py:class:`Segno`
    """
    try: # pragma: no cover
        import segno
    except (ModuleNotFoundError, ImportError) as e: # pragma: no cover
        raise ConfigurationError("Attempting to generate a TOTP QR code,"
                                 "but you didn't install the necessary `segno` library!") from e

    return segno.make(user_totp)


async def current_user() -> Any:
    """
    This method returns a user instance for token data attached to the
    current sanic app's context

    :returns: Current logged in ``User`` object
    :rtype: populated :py:attr:`user_class` attribute of the logged in :py:class:`~sanic_beskar.Beskar` instance
    :raises: :py:exc:`~sanic_beskar.BeskarError` if no user identified
    """
    user_id = current_user_id()
    guard = current_guard()
    user = await guard.user_class.identify(user_id)
    BeskarError.require_condition(
        user is not None,
        "Could not identify the current user from the current id",
    )
    return user


async def current_rolenames() -> set:
    """
    This method returns the names of all roles associated with the current user

    :returns: Set of roles for currently logged in users
    :rtype: set
    """
    token_data = get_token_data_from_app_context()
    if 'rls' not in token_data:
        # This is necessary so our set arithmetic works correctly
        return set(['non-empty-but-definitely-not-matching-subset'])

    return set(r.strip() for r in token_data['rls'].split(','))


def current_custom_claims() -> dict:
    """
    This method returns any custom claims in the current token

    :returns: Custom claims for currently logged in user
    :rtype: dict
    """
    token_data = get_token_data_from_app_context()
    return {k: v for (k, v) in token_data.items() if k not in RESERVED_CLAIMS}
