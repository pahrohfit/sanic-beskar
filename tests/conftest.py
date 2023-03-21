from sanic_testing import TestManager

from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

import pytest
import warnings
import copy

from tortoise import Tortoise, run_async
from sanic.log import logger
from sanic.exceptions import SanicException

from sanic_beskar.base import Beskar

from models import ValidatingUser, MixinUser, User, TotpUser
from server import create_app, _guard, _mail

import async_sender

import nest_asyncio
nest_asyncio.apply()


# Hack for using the same DB instance directly and within the app
async def init(db_path=None):
    await Tortoise.init(
        db_url=db_path,
        modules={'models': ["models"]},
    )
    await Tortoise.generate_schemas()


@pytest.fixture(params=["jwt", "paseto"])
def app(tmpdir_factory, request, monkeypatch):

    db_path = tmpdir_factory.mktemp(
        "sanic-beskar-test",
        numbered=True,
    ).join("sqlite.db")
    logger.info(f'Using DB_Path: {str(db_path)}')
    run_async(init(db_path=f'sqlite://{str(db_path)}'))

    # Use the fixture params to test all our token providers
    monkeypatch.setenv('SANIC_BESKAR_TOKEN_PROVIDER', request.param)

    sanic_app = create_app(db_path=f'sqlite://{str(db_path)}')
    TestManager(sanic_app)
    # Hack to do some poor code work in the app for some workarounds for broken fucntions under pytest
    sanic_app.config['PYTESTING'] = True
    sanic_app.prepare()

    sanic_app.config.SUPPRESS_SEND = 1  # Don't actually send mails
    #_mail.init_app(sanic_app)

    yield sanic_app
    sanic_app = None


@pytest.fixture(scope="session")
def user_class():
    """
    This fixture simply fetches the user_class to be used in testing
    """
    return User


@pytest.fixture(scope="session")
def mixin_user_class():
    """
    This fixture simply fetches the mixin user_class to be used in testing
    """
    return MixinUser


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
    """
    with app.app_context():
        stock_config = app.config.copy()
        yield
        app.config = stock_config.copy()
    """
    stock_config = copy.copy(app.config)
    yield
    app.config = copy.copy(stock_config)


@pytest.fixture
def client(app):
    yield app.asgi_client


@pytest.fixture()
def mock_users(user_class, default_guard):

    async def _get_user(username: str = None,
                        class_name: object = user_class,
                        guard_name: object = default_guard,
                        **kwargs):
        if not username:
            raise SanicException("You must supply a valid test user name!")

        # Set a default password of `something_secure`, unless one is provided
        password = guard_name.hash_password(kwargs.get('password', 'something_secure'))
        if kwargs.get('password'):
            # If one is provided, and already a hash, use it instead
            if guard_name.pwd_ctx.identify(str(kwargs['password'])):
                password = kwargs['password']

        email = kwargs.get('email', f"beskar_{username}@mock.com")

        # TODO: This is ugly, gotta be a nicer way
        if kwargs.get('id'):
            return await class_name.create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get('roles', ""),
                is_active=kwargs.get('is_active', True),
                id=kwargs['id'],
            )
        if kwargs.get('totp'):
            return await class_name.create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get('roles', ""),
                is_active=kwargs.get('is_active', True),
                totp=kwargs.get('totp'),
            )
        else:
            return await class_name.create(
                username=username,
                email=email,
                password=password,
                roles=kwargs.get('roles', ""),
                is_active=kwargs.get('is_active', True),
            )

    return _get_user


@pytest.fixture(autouse=False)
def no_token_validation(monkeypatch):
    """
    Monkeypatch to prevent token validation from automatically
      taking place. Instead, allow manual validation for testing
      purposes, when this fixture is included.
    """
    def mockreturn(*args, **kwargs):
        return True

    monkeypatch.setattr(Beskar, "_validate_token_data", mockreturn)


@pytest.fixture(autouse=True)
def no_email_sending(monkeypatch):
    """
    Monkeypatch to prevent emails from actually attempting to be
      sent from async_sender.
    """
    async def mock_send_message(*args, **kwargs):
        pass

    monkeypatch.setattr(async_sender.api.Mail, "send_message", mock_send_message)

@pytest.fixture(autouse=True)
def speed_up_passlib_for_pytest_only(default_guard):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        default_guard.pwd_ctx.update(pkdbf2_sha512__default_rounds=1)
        default_guard.pwd_ctx.update(bcrypt__default_rounds=1)
