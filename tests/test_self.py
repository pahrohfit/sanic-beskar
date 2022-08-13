from copy import deepcopy
import warnings
import pendulum
import plummet
import pytest
import ujson

from httpx import Cookies

from passlib.totp import generate_secret

from passlib.exc import (
    InvalidTokenError,
    MalformedTokenError,
    UsedTokenError,
)

from sanic.log import logger

from sanic_beskar import Beskar
from sanic_beskar.exceptions import (
    AuthenticationError,
    BlacklistedError,
    ClaimCollisionError,
    EarlyRefreshError,
    ExpiredAccessError,
    ExpiredRefreshError,
    InvalidUserError,
    MissingClaimError,
    MissingUserError,
    MisusedRegistrationToken,
    MisusedResetToken,
    BeskarError,
    LegacyScheme,
    TOTPRequired,
    ConfigurationError,
)
from sanic_beskar.constants import (
    AccessType,
    DEFAULT_TOKEN_ACCESS_LIFESPAN,
    DEFAULT_TOKEN_REFRESH_LIFESPAN,
    DEFAULT_TOKEN_HEADER_NAME,
    DEFAULT_TOKEN_HEADER_TYPE,
    IS_REGISTRATION_TOKEN_CLAIM,
    IS_RESET_TOKEN_CLAIM,
    REFRESH_EXPIRATION_CLAIM,
    VITAM_AETERNUM,
)


class TestBeskar:
    def test__validate_user_class__fails_if_class_has_no_lookup_classmethod(
        self,
        default_guard,
    ):
        class NoLookupUser:
            @classmethod
            def identify(cls, id):
                pass

        with pytest.raises(BeskarError) as err_info:
            default_guard._validate_user_class(NoLookupUser)
        assert "must have a lookup class method" in err_info.value.message

    def test__validate_user_class__fails_if_class_has_no_identify_classmethod(
        self,
        default_guard,
    ):
        class NoIdentifyUser:
            @classmethod
            def lookup(cls, username):
                pass

        with pytest.raises(BeskarError) as err_info:
            default_guard._validate_user_class(NoIdentifyUser)
        assert "must have an identify class method" in err_info.value.message

    def test__validate_user_class__fails_if_class_has_no_identity_attribute(
        self,
        default_guard,
    ):
        class NoIdentityUser:
            rolenames = []
            password = ""

            @classmethod
            def identify(cls, id):
                pass

            @classmethod
            def lookup(cls, username):
                pass

        with pytest.raises(BeskarError) as err_info:
            default_guard._validate_user_class(NoIdentityUser)
        assert "must have an identity attribute" in err_info.value.message

    def test__validate_user_class__fails_if_class_has_no_rolenames_attribute(
        self,
        default_guard,
    ):
        class NoRolenamesUser:
            identity = 0
            password = ""

            @classmethod
            def identify(cls, id):
                pass

            @classmethod
            def lookup(cls, username):
                pass

        with pytest.raises(BeskarError) as err_info:
            default_guard._validate_user_class(NoRolenamesUser)
        assert "must have a rolenames attribute" in err_info.value.message

    def test__validate_user_class__fails_if_class_has_no_password_attribute(
        self,
        default_guard,
    ):
        class NoPasswordUser:
            identity = 0
            rolenames = []

            @classmethod
            def identify(cls, id):
                pass

            @classmethod
            def lookup(cls, username):
                pass

        with pytest.raises(BeskarError) as err_info:
            default_guard._validate_user_class(NoPasswordUser)
        assert "must have a password attribute" in err_info.value.message

    async def test_rbac_policy_load(self, app, user_class):
        """
        This test verifies the authenticate_totp() function, for use
        with TOTP two factor authentication.
        """

        app.config["BESKAR_RBAC_POLICY"] = "testing"
        with pytest.raises(ConfigurationError):
            Beskar(app, user_class)

    def test__audit(self, app, user_class):
        """
        This test will ensure we get proper validation of any custom PASSWORD_POLICY
        """

        _default_config = deepcopy(app.config)

        # Check jacked up SECRET_KEY raises proper error
        app.config['SECRET_KEY'] = None
        with pytest.raises(ConfigurationError) as err_info:
            Beskar(app, user_class)
        assert 'There must be a SECRET_KEY app config setting set' in err_info.value.message
        app.config['SECRET_KEY'] = 'weak'
        with pytest.raises(ConfigurationError) as err_info:
            Beskar(app, user_class)
        assert 'your SECRET_KEY is weak in legnth' in err_info.value.message
        app.config['I_MAKE_POOR_CHOICES'] = True
        assert Beskar(app, user_class)

        app.config = deepcopy(_default_config) # reset
        # Check too short of a password length raises proper error
        app.config['BESKAR_PASSWORD_POLICY'] = {'length': 7}
        with pytest.raises(ConfigurationError) as err_info:
            Beskar(app, user_class)
        assert 'your password policy secret key legnth is weak!' in err_info.value.message
        app.config['I_MAKE_POOR_CHOICES'] = True
        assert Beskar(app, user_class)

        app.config = deepcopy(_default_config) # reset
        # Test bad PASETO version
        app.config['BESKAR_PASETO_VERSION'] = 99
        with pytest.raises(ConfigurationError) as err_info:
            Beskar(app, user_class)

        app.config = deepcopy(_default_config) # reset
        # Test bad PASETO version
        app.config['BESKAR_PASSWORD_POLICY'] = {'attempt_lockout': 0}
        with pytest.warns(match="A PASSWORD_POLICY['attempt_lockout'] value of 0 "):
            Beskar(app, user_class)
