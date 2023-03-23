from functools import wraps
from typing import Callable, Any, Union

from sanic import Request

from sanic_beskar.exceptions import (
    BeskarError,
    MissingRoleError,
    MissingRightError,
    MissingToken,
)


from sanic_beskar.utilities import (
    current_guard,
    add_token_data_to_app_context,
    app_context_has_token_data,
    remove_token_data_from_app_context,
    current_rolenames,
)


async def _verify_and_add_token(request: Request, optional: bool = False) -> None:
    """
    This helper method just checks and adds token data to the app context.
    If optional is False and the header is missing the token, just returns.

    Will not add token data if it is already present.

    Only used in this module

    Args:
        request (sanic.Request): Current Sanic ``Request``
        optional (bool, optional): Token is not required. Defaults to False.

    Raises:
        MissingToken: Token is required and not present.
    """
    if not app_context_has_token_data():
        guard = current_guard()
        try:
            token = guard.read_token(request=request)
        except MissingToken as err:
            if optional:
                return
            raise err
        token_data = await guard.extract_token(token)
        add_token_data_to_app_context(token_data)


def auth_required(method: Callable) -> Callable[..., Any]:
    """
    This decorator is used to ensure that a user is authenticated before
    being able to access a sanic route. It also adds the current user to the
    current sanic context.

    Args:
        method (Callable): Function or route to protect.

    Returns:
        None: Decorator

    Raises:
        MissingToken: No authenticated user token is available to authorize.
    """

    @wraps(method)
    async def wrapper(request: Request, *args: tuple, **kwargs: dict) -> Any:
        # TODO: hack to work around class based views
        if not isinstance(request, Request):
            if isinstance(args[0], Request):
                request = args[0]
        await _verify_and_add_token(request=request)
        try:
            return await method(request, *args, **kwargs)
        finally:
            remove_token_data_from_app_context()

    return wrapper


def auth_accepted(method: Callable) -> Callable[..., Any]:
    """
    This decorator is used to allow an authenticated user to be identified
    while being able to access a sanic route, and adds the current user to the
    current sanic context.

    Args:
        method (Callable): Function or route to protect.

    Returns:
        None: Decorator
    """
    @wraps(method)
    async def wrapper(request: Request, *args: tuple, **kwargs: dict) -> Any:
        # TODO: hack to work around class based views
        if not isinstance(request, Request):
            if isinstance(args[0], Request):
                request = args[0]
        try:
            await _verify_and_add_token(request, optional=True)
            return await method(request, *args, **kwargs)
        finally:
            remove_token_data_from_app_context()
    return wrapper


def roles_required(*required_rolenames: Union[list, set]) -> Callable[..., Any]:
    """
    This decorator ensures that any uses accessing the decorated route have all
    the needed roles to access it. If an :py:func:`auth_required` decorator is not
    supplied already, this decorator will implicitly check :py:func:`auth_required`
    first

    Args:
        required_rolenames (Union[list, set]): Role names required to be present
            in the authenticated users ``roles`` attribute.

    Returns:
        None: Decorator

    Raises:
        sanic_beskar.BeskarError: `roles_disabled` for this application.
        MissingRoleError: Missing required role names in user ``roles`` attribute.
        MissingTokenError: Token missing in ``Sanic.Request``
    """

    def decorator(method: Callable) -> Callable:
        @wraps(method)
        async def wrapper(request: Request, *args: tuple, **kwargs: dict) -> Any:
            BeskarError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
            # TODO: hack to work around class based views
            if not isinstance(request, Request):
                if isinstance(args[0], Request):
                    request = args[0]
            await _verify_and_add_token(request)
            try:
                MissingRoleError.require_condition(
                    not {*required_rolenames} - {*(await current_rolenames())},
                    'This endpoint requires all the following roles: '
                    f'[{required_rolenames}]',
                )
                return await method(request, *args, **kwargs)
            finally:
                remove_token_data_from_app_context()

        return wrapper

    return decorator


def rights_required(*required_rights: Union[list, set]) -> Callable[..., Any]:
    """
    This decorator ensures that any uses accessing the decorated route have all
    the needed rights to access it. If an :py:func:`auth_required` decorator is not
    supplied already, this decorator will implicitly check :py:func:`auth_required`
    first.

    Args:
        required_rights (Union[list, set]): Right names required to be present,
            based upon the implied rights in the authenticated users ``roles`` attribute
            breakdown.

    Returns:
        None: Decorator

    Raises:
        sanic_beskar.BeskarError: `roles_disabled` for this application.
        MissingRightError: Missing required rights in user ``roles`` attribute breakdown.
        MissingTokenError: Token missing in ``Sanic.Request``
    """

    def decorator(method: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(method)
        async def wrapper(request: Request, *args: tuple, **kwargs: dict) -> Any:
            BeskarError.require_condition(
                current_guard().rbac_definitions != {},
                "This feature is not available because RBAC is not enabled",
            )
            # TODO: hack to work around class based views
            if not isinstance(request, Request):
                if isinstance(args[0], Request):
                    request = args[0]
            await _verify_and_add_token(request)
            try:
                current_roles = await current_rolenames()
                for right in required_rights:
                    BeskarError.require_condition(
                        right in current_guard().rbac_definitions,
                        'This endpoint requires a right which is not otherwise defined: '
                        f'[{right}]',
                    )
                    MissingRightError.require_condition(
                        not {*current_roles}.isdisjoint(
                            {*(current_guard().rbac_definitions[right])}
                        ),
                        'This endpoint requires all the following rights: '
                        f'[{required_rights}]',
                    )
                return await method(request, *args, **kwargs)
            finally:
                remove_token_data_from_app_context()

        return wrapper

    return decorator


def roles_accepted(*accepted_rolenames: Union[list, set]) -> Callable[..., Any]:
    """
    This decorator ensures that any uses accessing the decorated route have one
    of the needed roles to access it. If an :py:func:`auth_required` decorator is not
    supplied already, this decorator will implicitly check :py:func:`auth_required`
    first

    Args:
        accepted_rolenames (Union[list, set]): Role names, at least one of which is
            required to be present, in the authenticated users ``roles`` attribute.

    Returns:
        None: Decorator
    """

    def decorator(method: Callable) -> Callable[..., Any]:
        @wraps(method)
        async def wrapper(request: Request, *args: tuple, **kwargs: dict) -> Any:
            BeskarError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
            # TODO: hack to work around class based views
            if not isinstance(request, Request):
                if isinstance(args[0], Request):
                    request = args[0]
            await _verify_and_add_token(request)
            try:
                MissingRoleError.require_condition(
                    not {*(await current_rolenames())}.isdisjoint(accepted_rolenames),
                    'This endpoint requires one of the following roles: '
                    f'[{accepted_rolenames}]',
                )
                return await method(request, *args, **kwargs)
            finally:
                remove_token_data_from_app_context()

        return wrapper

    return decorator
