from io import BytesIO, StringIO

import pendulum
import pytest
from sanic import Sanic
from sanic_beskar.exceptions import (
    BeskarError,
    ConfigurationError,
)
from sanic_beskar.utilities import (
    add_token_data_to_app_context,
    app_context_has_token_data,
    current_custom_claims,
    current_guard,
    current_rolenames,
    current_user,
    current_user_id,
    duration_from_string,
    generate_totp_qr,
    get_request,
    is_valid_json,
    normalize_rbac,
    remove_token_data_from_app_context,
)
from ujson import dumps


class TestBeskarUtilities:
    def test_app_context_has_token_data(self):
        """
        This test verifies that the app_context_has_token_data method can
        determine if token_data has been added to the app context yet
        """
        assert not app_context_has_token_data()
        add_token_data_to_app_context({"a": 1})
        assert app_context_has_token_data()
        remove_token_data_from_app_context()
        assert not app_context_has_token_data()

    def test_remove_token_data_from_app_context(self):
        """
        This test verifies that token data can be removed from an app context.
        It also verifies that attempting to remove the data if it does not
        exist there does not cause an exception
        """
        token_data = {"a": 1}
        add_token_data_to_app_context(token_data)
        assert Sanic.get_app().ctx.token_data == token_data
        remove_token_data_from_app_context()
        assert not hasattr(Sanic.get_app().ctx, "token_data")
        remove_token_data_from_app_context()

    async def test_current_user_id(self):
        """
        This test verifies that the current user id can be successfully
        determined based on token data that has been added to the current
        sanic app's context.
        """
        token_data = {}
        add_token_data_to_app_context(token_data)
        with pytest.raises(BeskarError) as err_info:
            await current_user()
        assert "Could not fetch an id" in str(err_info.value)

        token_data = {"id": 31}
        add_token_data_to_app_context(token_data)
        assert current_user_id() == 31

    async def test_current_user(self, mock_users):
        """
        This test verifies that the current user can be successfully
        determined based on token data that has been added to the current
        sanic app's context.
        """
        token_data = {}
        add_token_data_to_app_context(token_data)
        with pytest.raises(BeskarError) as err_info:
            await current_user()
        assert "Could not fetch an id" in str(err_info.value)

        token_data = {"id": 31}
        add_token_data_to_app_context(token_data)
        with pytest.raises(BeskarError) as err_info:
            await current_user()
        assert "Could not identify the current user" in str(err_info.value)

        the_dude = await mock_users(username="the_dude", password="Abides", id=13)
        token_data = {"id": 13}
        add_token_data_to_app_context(token_data)
        assert await current_user() == the_dude

    async def test_current_rolenames(self):
        """
        This test verifies that the rolenames attached to the current user
        can be extracted from the token data that has been added to the
        current sanic app's context
        """
        token_data = {}
        add_token_data_to_app_context(token_data)
        assert (await current_rolenames()) == set(["non-empty-but-definitely-not-matching-subset"])

        token_data = {"rls": "admin,operator"}
        add_token_data_to_app_context(token_data)
        assert (await current_rolenames()) == set(["admin", "operator"])

    def test_current_custom_claims(self):
        """
        This test verifies that any custom claims attached to the current token
        can be extracted from the token data that has been added to the
        current sanic app's context
        """
        token_data = dict(
            id=13,
            jti="whatever",
            duder="brief",
            el_duderino="not brief",
        )
        add_token_data_to_app_context(token_data)
        assert current_custom_claims() == dict(
            duder="brief",
            el_duderino="not brief",
        )

    def test_duration_from_string_success(self):
        """
        This test verifies that the duration_from_string method can be used to
        parse a duration from a string with expected formats
        """
        expected_duration = pendulum.duration(days=12, hours=1, seconds=1)
        computed_duration = duration_from_string("12d1h1s")
        assert computed_duration == expected_duration

        expected_duration = pendulum.duration(months=1, hours=2, minutes=3)
        computed_duration = duration_from_string("1 Month 2 Hours 3 minutes")
        assert computed_duration == expected_duration

        expected_duration = pendulum.duration(days=1, minutes=2, seconds=3)
        computed_duration = duration_from_string("1day,2min,3sec")
        assert computed_duration == expected_duration

        expected_duration = pendulum.duration(months=1, minutes=2)
        computed_duration = duration_from_string("1mo,2m")
        assert computed_duration == expected_duration

    def test_duration_from_string_fails(self):
        """
        This test verifies that the duration_from_string method raises a
        ConfiguationError exception if there was a problem parsing the string
        """
        with pytest.raises(ConfigurationError):
            duration_from_string("12x1y1z")
        with pytest.raises(ConfigurationError):
            duration_from_string("")

    async def test_segno_qr_generation(self, default_guard):
        """
        This test just verifies we can obtain a segno object
        for rendering QR codes for TOTP usage.
        """

        png_out = BytesIO()
        txt_out = StringIO()
        totp = default_guard.totp_ctx.new()
        qrcode = await generate_totp_qr(totp.to_json())
        assert qrcode

        qrcode.save(kind="png", out=png_out)
        qrcode.save(kind="txt", out=txt_out)

        assert png_out != BytesIO()
        assert isinstance(png_out, BytesIO)
        assert txt_out != StringIO()
        assert isinstance(txt_out, StringIO)

        with pytest.raises(TypeError):
            await generate_totp_qr(None)

    async def test_rbac_normalization(self):
        """
        This test verifies we can turn a standard {rolename: [rights]} RBAC
        dump into a form usable for efficient lookups in decorators.
        """

        test_rbac_dump = {
            "role1": ["righta", "rightb", "rightc", "rightd"],
            "role2": ["rightc"],
            "role3": ["rightb", "righte", "rightc"],
            "role4": ["righte", "righta", "rightb"],
        }

        good_rbac = {
            "righta": ["role1", "role4"],
            "rightb": ["role1", "role3", "role4"],
            "rightc": ["role1", "role2", "role3"],
            "rightd": ["role1"],
            "righte": ["role3", "role4"],
        }

        assert normalize_rbac(test_rbac_dump) == good_rbac

    async def test_is_valid_json(self):
        """
        This test verifies we can identify proper JSON.
        """

        assert await is_valid_json(dumps({"foo": "bar"}))
        assert not await is_valid_json([None])
        assert not await is_valid_json({"foo"})

    async def test_current_guard(self, default_guard):
        """
        This test verifies we get back the proper guard object
        """

        assert current_guard() == default_guard

    async def test_get_request(self):
        """
        This test verifies we get back the proper guard object
        """
        with pytest.raises(BeskarError):
            get_request(request=None)
