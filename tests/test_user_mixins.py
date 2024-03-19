import pytest
import sanic_beskar
import sanic_beskar.exceptions
from bson import ObjectId
from sanic_beskar.base import Beskar

# TODO: Fix Tortoise testing
from tests._models import MixinUserBeanie, MixinUserTortoise, MixinUserUmongo

ALL_MIXIN_MODELS = [MixinUserBeanie, MixinUserUmongo, MixinUserTortoise]


class TestUserMixin:
    """
    Unit tests for the ``sanic_beskar.orm`` included mixins
    """

    @pytest.mark.parametrize("mixin_user", ALL_MIXIN_MODELS)
    async def test_basic(self, app, mixin_user, mock_users, in_memory_tortoise_db):
        """
        test_basic

        Tests against the default guard to ensure base functionality
        """
        mixin_guard = sanic_beskar.Beskar(app, mixin_user)

        the_dude = await mock_users(
            username="the_dude",
            password="abides",
            guard_name=mixin_guard,
            class_name=mixin_user,
        )

        assert await mixin_guard.authenticate("the_dude", "abides") == the_dude
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await mixin_guard.authenticate("the_bro", "abides")
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await mixin_guard.authenticate("the_dude", "is_undudelike")
        await the_dude.delete()

    @pytest.mark.parametrize("mixin_user", ALL_MIXIN_MODELS)
    async def test_no_rolenames(self, app, mixin_user, mock_users, in_memory_tortoise_db):
        """
        test_no_rolenames

        Test missing ``user.roles`` attribute to ensure a blank list is at least available
        """
        mixin_guard = sanic_beskar.Beskar(app, mixin_user)

        the_noroles_dude = await mock_users(
            username="the_dude",
            password="abides",
            guard_name=mixin_guard,
            class_name=mixin_user,
        )

        assert the_noroles_dude.rolenames == []
        await the_noroles_dude.delete()

    @pytest.mark.parametrize("mixin_user", ALL_MIXIN_MODELS)
    async def test_lookups(self, app, mixin_user, mock_users, in_memory_tortoise_db):
        """
        test_lookups

        Tests to ensure the expected lookup functions work for the includes ORMs
        """
        mixin_guard = sanic_beskar.Beskar(app, mixin_user)

        the_dude = await mock_users(
            username="the_dude",
            password="abides",
            email="the_dude@mock.com",
            guard_name=mixin_guard,
            class_name=mixin_user,
        )

        assert await mixin_user.lookup(email="the_dude@mock.com") == the_dude
        assert await mixin_user.lookup(username="the_dude") == the_dude
        assert await mixin_user.lookup() is None
        assert await mixin_user.identify(id=the_dude.id) == the_dude
        fake_id = 999999999
        if isinstance(the_dude.id, ObjectId):
            fake_id = ObjectId()
        assert await mixin_user.identify(id=fake_id) is None
        assert await mixin_user.lookup(username=fake_id) is None

        if isinstance(the_dude.id, ObjectId):
            assert str(the_dude.identity) == str(the_dude.id)
        else:
            assert the_dude.identity == the_dude.id

        await the_dude.delete()

    async def test_totp(self, app, totp_user_class, mock_users):
        """
        test_totp

        Tests against OTP functionality of the included ORM mixins
        """
        totp_guard = sanic_beskar.Beskar(app, totp_user_class)

        the_dude = await mock_users(
            username="the_dude",
            password="abides",
            guard_name=totp_guard,
            class_name=totp_user_class,
            totp="mock",
        )
        assert the_dude.totp == "mock"
        assert app.config.get("BESKAR_TOTP_ENFORCE", True) is True

        # good creds, missing TOTP
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "abides")
        assert e.type is sanic_beskar.exceptions.TOTPRequired

        # bad creds
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "is_undudelike")
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        # bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await totp_guard.authenticate_totp("the_dude", 80085)

        # good creds, bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "abides", 80085)
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        # bad creds, bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "is_undudelike", 80085)
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        """
        Verify its ok to call `authenticate` w/o a `token`, for a required user,
            while `BESKAR_TOTP_ENFORCE` is set to `False`
        """
        app.config.BESKAR_TOTP_ENFORCE = False
        _totp_optional_guard = Beskar(app, totp_user_class)
        # good creds, missing TOTP
        _optional_the_dude = await _totp_optional_guard.authenticate("the_dude", "abides")
        assert _optional_the_dude == the_dude

        await the_dude.delete()
