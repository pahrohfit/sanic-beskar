import functools

from sanic_beskar.exceptions import (
    BeskarError,
    MissingRoleError,
    MissingToken,
)


from sanic_beskar.utilities import (
    current_guard,
    add_token_data_to_app_context,
    app_context_has_token_data,
    remove_token_data_from_app_context,
    current_rolenames,
)


async def _verify_and_add_token(request, optional=False):
    """
    This helper method just checks and adds token data to the app context.
    If optional is False and the header is missing the token, just returns.

    Will not add token data if it is already present.

    Only use in this module
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


def auth_required(method):
    """
    This decorator is used to ensure that a user is authenticated before
    being able to access a sanic route. It also adds the current user to the
    current sanic context.
    """

    @functools.wraps(method)
    async def wrapper(request, *args, **kwargs):
        await _verify_and_add_token(request)
        try:
            return await method(request, *args, **kwargs)
        finally:
            remove_token_data_from_app_context()

    return wrapper


def auth_accepted(method):
    """
    This decorator is used to allow an authenticated user to be identified
    while being able to access a sanic route, and adds the current user to the
    current sanic context.
    """
    @functools.wraps(method)
    async def wrapper(request, *args, **kwargs):
        try:
            await _verify_and_add_token(request, optional=True)
            return await method(request, *args, **kwargs)
        finally:
            remove_token_data_from_app_context()
    return wrapper


def roles_required(*required_rolenames):
    """
    This decorator ensures that any uses accessing the decorated route have all
    the needed roles to access it. If an :py:func:`auth_required` decorator is not
    supplied already, this decorator will implicitly check :py:func:`auth_required`
    first
    """

    def decorator(method):
        @functools.wraps(method)
        async def wrapper(request, *args, **kwargs):
            BeskarError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
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


def roles_accepted(*accepted_rolenames):
    """
    This decorator ensures that any uses accessing the decorated route have one
    of the needed roles to access it. If an :py:func:`auth_required` decorator is not
    supplied already, this decorator will implicitly check :py:func:`auth_required`
    first
    """

    def decorator(method):
        @functools.wraps(method)
        async def wrapper(request, *args, **kwargs):
            BeskarError.require_condition(
                not current_guard().roles_disabled,
                "This feature is not available because roles are disabled",
            )
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
