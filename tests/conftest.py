import asyncio
import uvloop

# asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from sanic_testing import TestManager  # type: ignore

import copy
import warnings
from typing import Any

import async_sender  # type: ignore
import pytest
from sanic import Sanic, json
from sanic.views import HTTPMethodView
from sanic.exceptions import SanicException
from sanic.log import logger

from mongomock_motor import AsyncMongoMockClient  # type: ignore[import-untyped]
from beanie import init_beanie
from tortoise import Tortoise
from tortoise.contrib.test import _init_db, getDBConfig

from tests._models import TotpUser, ValidatingUser, MixinUserBeanie

import sanic_beskar
from sanic_beskar.base import Beskar
from sanic_beskar.exceptions import BeskarError
from async_sender import Mail

from ujson import dumps as ujson_dumps
from ujson import loads as ujson_loads


_guard = Beskar()
_mail = Mail()


@pytest.fixture(params=["jwt", "paseto"])
async def app(request, monkeypatch):
    """
    Sanic App instance for unit testing
    """

    # Use the fixture params to test all our token providers
    monkeypatch.setenv("SANIC_BESKAR_TOKEN_PROVIDER", request.param)

    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic("sanic-testing", dumps=ujson_dumps, loads=ujson_loads)
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.state.mode = "Mode.DEBUG"
    sanic_app.config.TESTING = True
    sanic_app.config["PYTESTING"] = True
    sanic_app.config.SECRET_KEY = "top secret 4nd comPLex radness!!"

    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    _guard.init_app(sanic_app, MixinUserBeanie)
    _guard.rbac_definitions = {
        "sooper_access_right": ["admin", "uber_admin"],
        "lame_access_right": ["not_admin"],
    }
    sanic_app.ctx.mail = _mail

    @sanic_app.route("/unprotected")
    def unprotected(request):
        """
        Endpoint without any security decorators
        """
        return json({"message": "success"})

    @sanic_app.route("/kinda_protected")
    @sanic_beskar.auth_accepted
    async def kinda_protected(request):
        """
        Endpoint that allows an authentication header (to set a user)
        """
        try:
            authed_user = await sanic_beskar.current_user()
            return json({"message": "success", "user": authed_user.username})
        except BeskarError:
            return json({"message": "success", "user": None})

    class ProtectedView(HTTPMethodView):
        """
        Class based Endpoint that requires an authentication header, via `class` based setup
        """

        @sanic_beskar.auth_required
        async def get(self, request):
            """
            Endpoint that requires an authentication header, via `class` based setup
            """
            return json({"message": "success"})

    sanic_app.add_route(ProtectedView.as_view(), "/protected_class")

    @sanic_app.route("/protected_route")
    @sanic_beskar.auth_required
    async def protected_route(request):
        """
        Endpoint requiring basic authentication header
        """
        return json({"message": "success"})

    @sanic_app.route("/rbac_protected")
    @sanic_beskar.auth_required
    @sanic_beskar.rights_required("sooper_access_right")
    async def rights_protected(request):
        """
        Endpoint looking for `sooper_access_right` RBAC rights
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_required")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_required("admin")
    async def protected_admin_required(request):
        """
        Endpoint requiring the user has an 'admin' role
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_required")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_required("admin", "operator")
    async def protected_admin_and_operator_required(request):
        """
        Endpoint requiring both 'admin' and 'operator' roles
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_accepted")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_accepted("admin", "operator")
    async def protected_admin_and_operator_accepted(request):
        """
        endpoint that requires 'admin' *and*/*or* 'operator' role
        """
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_required")
    @sanic_beskar.roles_required("admin")
    async def undecorated_admin_required(request):
        """
        Endpoint that doesn't use both decorators (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_accepted")
    @sanic_beskar.roles_accepted("admin")
    async def undecorated_admin_accepted(request):
        """
        Endpoint that doesn't use both decorators (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/reversed_decorators")
    @sanic_beskar.roles_required("admin", "operator")
    @sanic_beskar.auth_required
    async def reversed_decorators(request):
        """
        Endpoint with decorators in a different order (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/registration_confirmation")
    def reg_confirm(request):
        """
        Endpoint for registration testing
        """
        return json({"message": "fuck"})

    TestManager(sanic_app)

    # Init beanie
    client = AsyncMongoMockClient()
    await init_beanie(database=client.db_name, document_models=[MixinUserBeanie])
    import logging

    logging.basicConfig(level=logging.DEBUG)

    # register_tortoise(
    #    sanic_app, db_url="sqlite://:memory:", modules={"models": ["tests._models"]}, generate_schemas=True
    # )

    return sanic_app
    # Sanic._app_registry.clear()


@pytest.fixture(scope="session")
def user_class():
    """
    This fixture simply fetches the user_class to be used in testing
    """
    return MixinUserBeanie


@pytest.fixture(scope="session")
def mixin_user_class():
    """
    This fixture simply fetches the mixin user_class to be used in testing
    """
    return MixinUserBeanie


@pytest.fixture(scope="session")
def totp_user_class():
    """
    This fixture simply fetches the mixin user_class to be used in testing
    """
    return TotpUser


@pytest.fixture(scope="session")
def validating_user_class():
    """
    This fixture simply fetches the validating user_class to be used in testing
    """
    return ValidatingUser


@pytest.fixture(scope="session")
def default_guard():
    """
    This fixtures fetches the sanic-beskar instance to be used in testing
    """
    return _guard


@pytest.fixture(scope="session")
def mail():
    """
    This fixture simply fetches the db instance to be used in testing
    """
    return _mail


@pytest.fixture(autouse=True)
def clean_sanic_app_config(app):
    """
    This fixture ensures a clean `app.config` is available for each round
        of testing.
    """
    stock_config = copy.copy(app.config)
    yield
    app.config = copy.copy(stock_config)


@pytest.fixture
def client(app):
    """
    Fixture to hold the `asgi_client` test client
    """
    yield app.asgi_client


@pytest.fixture()
def mock_users(user_class, default_guard):
    """
    Fixture to hold generator for test users for unit testing
    """

    async def _get_user(
        username: str, class_name: Any = user_class, guard_name: Any = default_guard, **kwargs
    ):
        """
        Generator for test user creations

        Args:
            username (str): Username to use.
            class_name (obj, optional): User class to use. Defaults to user_class.
            guard_name (obj, optional): Beskar guard instance to use. Defaults to default_guard.

        Raises:
            SanicException: Missing `username`

        Returns:
            obj: Generated temp user object
        """
        if not username:
            raise SanicException("You must supply a valid test user name!")

        # Set a default password of `something_secure`, unless one is provided
        password = guard_name.hash_password(kwargs.get("password", "something_secure"))
        if kwargs.get("password"):
            # If one is provided, and already a hash, use it instead
            if guard_name.pwd_ctx.identify(str(kwargs["password"])):
                password = kwargs["password"]

        email = kwargs.get("email", f"beskar_{username}@mock.com")

        # TODO: This is ugly, gotta be a nicer way
        if kwargs.get("id"):
            return await class_name.cls_create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get("roles", ""),
                is_active=kwargs.get("is_active", True),
                id=kwargs["id"],
            )
        if kwargs.get("totp"):
            return await class_name.cls_create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get("roles", ""),
                is_active=kwargs.get("is_active", True),
                totp=kwargs.get("totp"),
            )
        else:
            return await class_name.cls_create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get("roles", ""),
                is_active=kwargs.get("is_active", True),
            )

    return _get_user


@pytest.fixture(autouse=False)
def no_token_validation(monkeypatch):
    """
    Monkeypatch to prevent token validation from automatically
      taking place. Instead, allow manual validation for testing
      purposes, when this fixture is included.
    """

    def _mockreturn(*args, **kwargs):
        """monkeypatcher to null out function"""
        return True

    monkeypatch.setattr(Beskar, "_validate_token_data", _mockreturn)


@pytest.fixture(autouse=True)
def no_email_sending(monkeypatch):
    """
    Monkeypatch to prevent emails from actually attempting to be
      sent from async_sender.
    """

    async def _mock_send_message(*args, **kwargs):
        """monkeypatcher to null out function"""
        pass

    monkeypatch.setattr(async_sender.api.Mail, "send_message", _mock_send_message)


@pytest.fixture(autouse=True)
def speed_up_passlib_for_pytest_only(default_guard):
    """
    Fixture to lower down the hashing rounds simply to speed up unit testing where
    the strength doesn't matter.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        default_guard.pwd_ctx.update(pkdbf2_sha512__default_rounds=1)
        default_guard.pwd_ctx.update(bcrypt__default_rounds=1)


@pytest.fixture(scope="session", autouse=False)
def in_memory_tortoise_db(request):
    """
    set up and tear down Tortoise as needed for testing

    hack brought to you by:
      https://github.com/tortoise/tortoise-orm/issues/1110#issuecomment-1521477988
    """
    config = getDBConfig(app_label="models", modules=["tests._models"])

    loop = asyncio.get_event_loop()
    loop.run_until_complete(_init_db(config))

    request.addfinalizer(lambda: loop.run_until_complete(Tortoise._drop_databases()))
