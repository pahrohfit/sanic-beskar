import builtins
import json
from unittest.mock import MagicMock, patch

import pytest
from webauthn.helpers import bytes_to_base64url

from sanic_beskar.exceptions import (
    ConfigurationError,
    PasskeyChallengeError,
    PasskeyError,
    PasskeyVerificationError,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

FAKE_CRED_ID = b"fake_credential_id_bytes"
FAKE_PUBKEY = b"fake_public_key_bytes"
FAKE_CHALLENGE = b"fake_challenge_bytes_32x"

# Minimal client JSON payloads (content doesn't matter — webauthn is fully mocked)
FAKE_REG_JSON = json.dumps(
    {
        "id": "ZmFrZQ",
        "rawId": "ZmFrZQ",
        "response": {"transports": ["internal"]},
        "type": "public-key",
    }
)
FAKE_AUTH_JSON = json.dumps(
    {
        "id": bytes_to_base64url(FAKE_CRED_ID),
        "rawId": bytes_to_base64url(FAKE_CRED_ID),
        "type": "public-key",
    }
)


def _make_cred_entry(cred_id: bytes = FAKE_CRED_ID, sign_count: int = 0) -> dict:
    """Return a stored credential dict matching the fake credential."""
    return {
        "id": bytes_to_base64url(cred_id),
        "public_key": bytes_to_base64url(FAKE_PUBKEY),
        "sign_count": sign_count,
        "transports": ["internal"],
    }


@pytest.fixture
def challenge_store():
    """
    Simple in-memory challenge store suitable for testing.
    Returns (store_fn, get_fn, backing_dict).
    """
    store: dict = {}

    async def _store(user_id: str, challenge: bytes, ttl: int) -> None:
        """Persist a challenge keyed by user_id."""
        store[user_id] = challenge

    async def _get(user_id: str) -> bytes | None:
        """Retrieve a stored challenge by user_id (non-consuming)."""
        return store.get(user_id)

    return _store, _get, store


@pytest.fixture
def webauthn_guard(default_guard, challenge_store, monkeypatch):
    """
    A Beskar guard instance wired with in-memory challenge store hooks and
    sensible WebAuthn defaults for unit testing.
    """
    store_fn, get_fn, _ = challenge_store
    monkeypatch.setattr(default_guard, "webauthn_store_challenge", store_fn)
    monkeypatch.setattr(default_guard, "webauthn_get_challenge", get_fn)
    monkeypatch.setattr(default_guard, "webauthn_rp_id", "localhost")
    monkeypatch.setattr(default_guard, "webauthn_rp_name", "Test App")
    monkeypatch.setattr(default_guard, "webauthn_origin", "http://localhost")
    monkeypatch.setattr(default_guard, "webauthn_challenge_ttl", 60)
    return default_guard


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBeskarWebAuthn:
    """Unit tests for WebAuthn/Passkey support"""

    # ------------------------------------------------------------------
    # Registration – generate options
    # ------------------------------------------------------------------

    async def test_generate_registration_options_returns_dict(self, webauthn_guard, mock_users):
        """
        generate_registration_options returns a JSON-safe dict and stores the
        challenge so it can be retrieved by user identity.
        """
        user = await mock_users("wauthn_reg_gen")

        mock_options = MagicMock()
        mock_options.challenge = FAKE_CHALLENGE

        with (
            patch("webauthn.generate_registration_options", return_value=mock_options),
            patch("webauthn.options_to_json", return_value='{"challenge": "dGVzdA"}'),
        ):
            result = await webauthn_guard.webauthn_generate_registration_options(user)

        assert result == {"challenge": "dGVzdA"}
        stored = await webauthn_guard.webauthn_get_challenge(str(user.identity))
        assert stored == FAKE_CHALLENGE

    async def test_generate_registration_options_no_hooks_raises(self, default_guard, mock_users):
        """
        Calling generate_registration_options without configuring the challenge
        hooks must raise ConfigurationError.
        """
        user = await mock_users("wauthn_reg_no_hooks")
        with pytest.raises(ConfigurationError, match="webauthn_store_challenge"):
            await default_guard.webauthn_generate_registration_options(user)

    # ------------------------------------------------------------------
    # Registration – verify response
    # ------------------------------------------------------------------

    async def test_verify_registration_response_success(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        A valid registration response is verified and the returned credential
        dict contains the expected keys with correct types.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_reg_verify")
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        mock_verified = MagicMock()
        mock_verified.credential_id = FAKE_CRED_ID
        mock_verified.credential_public_key = FAKE_PUBKEY
        mock_verified.sign_count = 0

        with patch("webauthn.verify_registration_response", return_value=mock_verified):
            result = await webauthn_guard.webauthn_verify_registration_response(user, FAKE_REG_JSON)

        assert result["id"] == bytes_to_base64url(FAKE_CRED_ID)
        assert result["public_key"] == bytes_to_base64url(FAKE_PUBKEY)
        assert result["sign_count"] == 0
        assert result["transports"] == ["internal"]

    async def test_verify_registration_response_no_challenge_raises(
        self, webauthn_guard, mock_users
    ):
        """
        If no challenge was stored for the user, verification must raise
        PasskeyChallengeError before touching the webauthn library.
        """
        user = await mock_users("wauthn_reg_no_challenge")
        with pytest.raises(PasskeyChallengeError, match="challenge not found"):
            await webauthn_guard.webauthn_verify_registration_response(user, FAKE_REG_JSON)

    async def test_verify_registration_response_library_error_raises(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        If the webauthn library raises during verification, it must be wrapped
        in a PasskeyVerificationError.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_reg_lib_err")
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        with patch(
            "webauthn.verify_registration_response",
            side_effect=ValueError("bad attestation"),
        ):
            with pytest.raises(PasskeyVerificationError, match="verification failed"):
                await webauthn_guard.webauthn_verify_registration_response(user, FAKE_REG_JSON)

    # ------------------------------------------------------------------
    # Authentication – generate options
    # ------------------------------------------------------------------

    async def test_generate_authentication_options_success(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        generate_authentication_options returns a dict and stores the challenge
        when the user has at least one registered credential.
        """
        user = await mock_users("wauthn_auth_gen")
        user.webauthn_credentials = [_make_cred_entry()]

        mock_options = MagicMock()
        mock_options.challenge = FAKE_CHALLENGE

        with (
            patch("webauthn.generate_authentication_options", return_value=mock_options),
            patch("webauthn.options_to_json", return_value='{"challenge": "dGVzdA"}'),
        ):
            result = await webauthn_guard.webauthn_generate_authentication_options(user)

        assert result == {"challenge": "dGVzdA"}
        stored = await webauthn_guard.webauthn_get_challenge(str(user.identity))
        assert stored == FAKE_CHALLENGE

    async def test_generate_authentication_options_no_credentials_raises(
        self, webauthn_guard, mock_users
    ):
        """
        A user with no registered Passkeys must raise PasskeyError.
        """
        user = await mock_users("wauthn_auth_no_creds")
        with pytest.raises(PasskeyError, match="no registered Passkeys"):
            await webauthn_guard.webauthn_generate_authentication_options(user)

    async def test_generate_authentication_options_no_hooks_raises(self, default_guard, mock_users):
        """
        Missing challenge hooks must raise ConfigurationError regardless of credentials.
        """
        user = await mock_users("wauthn_auth_no_hooks")
        user.webauthn_credentials = [_make_cred_entry()]
        with pytest.raises(ConfigurationError, match="webauthn_store_challenge"):
            await default_guard.webauthn_generate_authentication_options(user)

    # ------------------------------------------------------------------
    # Authentication – verify response
    # ------------------------------------------------------------------

    async def test_verify_authentication_response_success(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        A valid authentication response is verified, the sign count is updated
        in-place on the credential dict, and the user object is returned.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_auth_verify")
        cred_entry = _make_cred_entry(sign_count=5)
        user.webauthn_credentials = [cred_entry]
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        mock_verified = MagicMock()
        mock_verified.new_sign_count = 6

        with patch("webauthn.verify_authentication_response", return_value=mock_verified):
            result = await webauthn_guard.webauthn_verify_authentication_response(
                user, FAKE_AUTH_JSON
            )

        assert result is user
        assert cred_entry["sign_count"] == 6

    async def test_verify_authentication_response_no_challenge_raises(
        self, webauthn_guard, mock_users
    ):
        """
        Missing challenge must raise PasskeyChallengeError before anything else.
        """
        user = await mock_users("wauthn_auth_no_chal")
        user.webauthn_credentials = [_make_cred_entry()]
        with pytest.raises(PasskeyChallengeError, match="challenge not found"):
            await webauthn_guard.webauthn_verify_authentication_response(user, FAKE_AUTH_JSON)

    async def test_verify_authentication_response_unknown_credential_raises(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        If the credential_id in the response does not match any stored credential
        for the user, PasskeyVerificationError must be raised.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_auth_unk_cred")
        user.webauthn_credentials = [_make_cred_entry(cred_id=b"different_id")]
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        with pytest.raises(PasskeyVerificationError, match="No stored credential"):
            await webauthn_guard.webauthn_verify_authentication_response(user, FAKE_AUTH_JSON)

    async def test_verify_authentication_response_library_error_raises(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        If the webauthn library raises during verification the error must be
        wrapped in a PasskeyVerificationError.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_auth_lib_err")
        cred_entry = _make_cred_entry()
        user.webauthn_credentials = [cred_entry]
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        with patch(
            "webauthn.verify_authentication_response",
            side_effect=ValueError("invalid signature"),
        ):
            with pytest.raises(PasskeyVerificationError, match="verification failed"):
                await webauthn_guard.webauthn_verify_authentication_response(user, FAKE_AUTH_JSON)

    async def test_verify_authentication_response_malformed_json_raises(
        self, webauthn_guard, challenge_store, mock_users
    ):
        """
        A malformed JSON string must raise PasskeyVerificationError.
        """
        store_fn, _, _ = challenge_store
        user = await mock_users("wauthn_auth_malformed")
        user.webauthn_credentials = [_make_cred_entry()]
        await store_fn(str(user.identity), FAKE_CHALLENGE, 60)

        with pytest.raises(PasskeyVerificationError, match="Invalid WebAuthn credential"):
            await webauthn_guard.webauthn_verify_authentication_response(
                user, "not valid json at all {{{"
            )

    # ------------------------------------------------------------------
    # Library availability
    # ------------------------------------------------------------------

    async def test_require_webauthn_missing_library_raises(
        self, default_guard, mock_users, monkeypatch
    ):
        """
        If the webauthn library is not installed, generate_registration_options
        must raise ConfigurationError with a helpful install hint.
        """
        real_import = builtins.__import__

        def _block_webauthn(name: str, *args, **kwargs):
            """Intercept imports and raise ImportError for the webauthn module."""
            if name == "webauthn":
                raise ImportError("No module named 'webauthn'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_webauthn)
        user = await mock_users("wauthn_no_lib")

        with pytest.raises(ConfigurationError, match="sanic-beskar"):
            await default_guard.webauthn_generate_registration_options(user)

    # ------------------------------------------------------------------
    # ORM mixin helpers
    # ------------------------------------------------------------------

    async def test_beanie_mixin_get_webauthn_credential_found(self, mock_users):
        """
        BeanieUserMixin.get_webauthn_credential returns the matching cred dict.
        """
        user = await mock_users("wauthn_mixin_found")
        entry = _make_cred_entry()
        user.webauthn_credentials = [entry, _make_cred_entry(cred_id=b"other_id")]

        result = user.get_webauthn_credential(entry["id"])
        assert result is entry

    async def test_beanie_mixin_get_webauthn_credential_not_found(self, mock_users):
        """
        BeanieUserMixin.get_webauthn_credential returns None for an unknown ID.
        """
        user = await mock_users("wauthn_mixin_miss")
        user.webauthn_credentials = [_make_cred_entry()]

        result = user.get_webauthn_credential("does_not_exist")
        assert result is None

    async def test_beanie_mixin_get_webauthn_credential_empty_list(self, mock_users):
        """
        get_webauthn_credential returns None gracefully when the list is empty.
        """
        user = await mock_users("wauthn_mixin_empty")
        result = user.get_webauthn_credential("anything")
        assert result is None
