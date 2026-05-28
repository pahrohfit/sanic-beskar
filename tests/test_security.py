"""Security regression tests covering OWASP Top 10 attack vectors."""

import base64
import json as stdlib_json
import warnings as _warnings
from unittest.mock import MagicMock

import jwt as pyjwt
import pendulum
import plummet  # type: ignore
import pytest
from pyseto import Key as PasetoKey
from pyseto import Paseto as PasetoLib

from sanic_beskar.base import Beskar
from sanic_beskar.constants import AccessType, RESERVED_CLAIMS
from sanic_beskar.exceptions import (
    AuthenticationError,
    ClaimCollisionError,
    ConfigurationError,
    EarlyRefreshError,
    InvalidUserError,
    MisusedRegistrationToken,
    MisusedResetToken,
)


class TestBeskarSecurity:
    """
    Security regression tests covering common attack vectors from OWASP Top 10.

    These tests verify that sanic-beskar correctly rejects malicious inputs and
    enforces authentication/authorization invariants under adversarial conditions.
    Categories covered: A01 Broken Access Control, A02 Cryptographic Failures,
    A05 Security Misconfiguration, A07 Identification and Authentication Failures.
    """

    async def test_jwt_none_algorithm_rejected(self, default_guard):
        """
        OWASP A02 - Cryptographic Failures: alg-none attack.

        Verifies that a JWT with ``alg: none`` and no signature is rejected,
        guarding against the classic algorithm-confusion / alg-none attack
        where an attacker strips the signature and downgrades the algorithm.
        """
        if default_guard.token_provider != "jwt":
            pytest.skip("alg:none attack is JWT-specific")

        header = (
            base64.urlsafe_b64encode(stdlib_json.dumps({"typ": "JWT", "alg": "none"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(stdlib_json.dumps({"id": 1, "rls": "admin"}).encode())
            .rstrip(b"=")
            .decode()
        )
        forged_token = f"{header}.{payload}."

        with pytest.raises(Exception):
            await default_guard.extract_token(forged_token)

    async def test_jwt_wrong_secret_rejected(self, default_guard, mock_users):
        """
        OWASP A02 - Cryptographic Failures: token forgery via wrong secret.

        Verifies that a JWT signed with a different secret key is rejected,
        preventing an attacker who knows the JWT structure but not the signing
        secret from forging tokens with arbitrary claims.
        """
        if default_guard.token_provider != "jwt":
            pytest.skip("wrong-secret forgery test is JWT-specific")

        the_dude = await mock_users(username="the_dude")
        exp = pendulum.now("UTC").add(minutes=15).int_timestamp
        forged_token = pyjwt.encode(
            {"id": str(the_dude.identity), "rls": "admin", "exp": exp},
            "not_the_real_secret",
            algorithm="HS256",
        )

        with pytest.raises(Exception):
            await default_guard.extract_token(forged_token)

        await the_dude.delete()

    async def test_jwt_tampered_payload_rejected(self, default_guard, mock_users):
        """
        OWASP A02 - Cryptographic Failures: payload tampering.

        Verifies that altering the JWT payload after signing causes signature
        verification to fail, preventing privilege escalation by editing the
        roles or identity claims of an otherwise valid token.
        """
        if default_guard.token_provider != "jwt":
            pytest.skip("payload-tampering test is JWT-specific")

        the_dude = await mock_users(username="the_dude")
        with plummet.frozen_time("2017-05-24 10:38:45"):
            token = await default_guard.encode_token(the_dude)

        parts = token.split(".")
        padding = "=" * (4 - len(parts[1]) % 4)
        decoded_payload = stdlib_json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        decoded_payload["rls"] = "admin"
        tampered_b64 = (
            base64.urlsafe_b64encode(stdlib_json.dumps(decoded_payload).encode())
            .rstrip(b"=")
            .decode()
        )
        tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"

        with plummet.frozen_time("2017-05-24 10:38:46"):
            with pytest.raises(Exception):
                await default_guard.extract_token(tampered_token)

        await the_dude.delete()

    async def test_reserved_claim_collision_raises(self, default_guard, mock_users):
        """
        OWASP A01 - Broken Access Control: reserved claim collision.

        Verifies that supplying any reserved claim name in ``custom_claims``
        raises :class:`~sanic_beskar.exceptions.ClaimCollisionError`, preventing
        an attacker-controlled value from overriding an identity or expiry claim.
        """
        the_dude = await mock_users(username="the_dude")
        for reserved in RESERVED_CLAIMS:
            with pytest.raises(ClaimCollisionError):
                await default_guard.encode_token(the_dude, **{reserved: "evil"})
        await the_dude.delete()

    async def test_disabled_user_access_revoked(self, default_guard):
        """
        OWASP A01 - Broken Access Control: disabled account bypass.

        Verifies that a user whose ``is_valid()`` method returns ``False``
        is rejected by :meth:`~sanic_beskar.Beskar._check_user`, even when
        a structurally valid token is presented, preventing access by
        suspended or deactivated accounts.
        """
        disabled = MagicMock()
        disabled.is_valid.return_value = False

        with pytest.raises(InvalidUserError):
            default_guard._check_user(disabled)

    async def test_deleted_user_token_current_user_fails(self, default_guard, mock_users, client):
        """
        OWASP A01 - Broken Access Control: token surviving account deletion.

        Verifies that a token whose backing user record has been deleted causes
        :func:`~sanic_beskar.current_user` to return ``None``, ensuring routes
        that call ``current_user()`` cannot resolve a valid session to a
        non-existent account.  Token-only validation (without a DB lookup) is
        a separate concern and intentionally lightweight.
        """
        the_dude = await mock_users(username="the_dude")
        with plummet.frozen_time("2017-05-24 10:38:45"):
            headers = await default_guard.pack_header_for_user(the_dude)
        await the_dude.delete()

        with plummet.frozen_time("2017-05-24 10:38:46"):
            _, response = await client.get("/kinda_protected", headers=headers)
        assert response.status == 200
        assert response.json["user"] is None

    async def test_user_enumeration_constant_error(self, default_guard, mock_users):
        """
        OWASP A07 - Identification and Authentication Failures: user enumeration.

        Verifies that authenticating with an unknown username and authenticating
        with a valid username but wrong password both produce the same generic
        error message, preventing attackers from confirming which usernames
        exist in the system via differing server responses.
        """
        await mock_users(username="real_user")

        with pytest.raises(AuthenticationError) as exc_unknown:
            await default_guard.authenticate("no_such_user", "password")

        with pytest.raises(AuthenticationError) as exc_wrong_pass:
            await default_guard.authenticate("real_user", "wrong_password")

        assert str(exc_unknown.value) == str(exc_wrong_pass.value)

    async def test_empty_password_rejected(self, default_guard, mock_users):
        """
        OWASP A07 - Identification and Authentication Failures: blank credential.

        Verifies that an empty-string password is rejected by
        :meth:`~sanic_beskar.Beskar.authenticate`, guarding against
        misconfigured passlib contexts that might accept blank credentials.
        """
        await mock_users(username="the_dude")

        with pytest.raises(AuthenticationError):
            await default_guard.authenticate("the_dude", "")

    async def test_totp_replay_rejected(self, app, mock_users, totp_user_class):
        """
        OWASP A07 - Identification and Authentication Failures: TOTP replay.

        Verifies that a TOTP code which has already been accepted is rejected
        on a second authentication attempt, guarding against replay attacks
        where a network observer captures and resubmits a valid one-time code.
        """
        app.config.BESKAR_TOTP_SECRETS_TYPE = None
        totp_guard = Beskar(app, totp_user_class)
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            totp_guard.pwd_ctx.update(pbkdf2_sha512__default_rounds=1)

        totp = totp_guard.totp_ctx.new()
        the_dude = await mock_users(
            username="the_dude_totp",
            password="abides",
            class_name=totp_user_class,
            guard_name=totp_guard,
            totp=totp.to_json(),
        )

        token = totp.generate().token

        the_dude = await totp_guard.authenticate_totp("the_dude_totp", token)
        assert the_dude.totp_last_counter

        with pytest.raises(Exception):
            await totp_guard.authenticate_totp("the_dude_totp", token)

    async def test_weak_secret_key_requires_bypass(self, app, default_guard):
        """
        OWASP A05 - Security Misconfiguration: weak SECRET_KEY enforcement.

        Verifies that a SECRET_KEY shorter than the configured minimum raises
        :class:`~sanic_beskar.exceptions.ConfigurationError` from
        :meth:`~sanic_beskar.Beskar.audit`, and that the only escape hatch is
        the explicit ``I_MAKE_POOR_CHOICES`` opt-in, making misconfiguration
        a hard failure rather than a silent degradation.
        """
        app.config.SECRET_KEY = "short"
        app.config.I_MAKE_POOR_CHOICES = False

        with pytest.raises(ConfigurationError):
            default_guard.audit()

        app.config.I_MAKE_POOR_CHOICES = True
        default_guard.audit()

    async def test_registration_token_rejected_as_access(self, default_guard, mock_users):
        """
        OWASP A01 - Broken Access Control: token purpose confusion.

        Verifies that a registration-confirmation token (``is_ert`` claim present)
        is rejected when presented as a bearer token on a protected route.
        These one-shot tokens must not be reusable for general authentication.
        """
        the_dude = await mock_users(username="the_dude")
        token = await default_guard.encode_token(the_dude, is_registration_token=True)

        with pytest.raises(MisusedRegistrationToken):
            await default_guard.extract_token(token, access_type=AccessType.access)

        await the_dude.delete()

    async def test_reset_token_rejected_as_access(self, default_guard, mock_users):
        """
        OWASP A01 - Broken Access Control: token purpose confusion.

        Verifies that a password-reset token (``is_prt`` claim present) is
        rejected when presented as a bearer token on a protected route,
        preventing a leaked reset link from being used for account takeover.
        """
        the_dude = await mock_users(username="the_dude")
        token = await default_guard.encode_token(the_dude, is_reset_token=True)

        with pytest.raises(MisusedResetToken):
            await default_guard.extract_token(token, access_type=AccessType.access)

        await the_dude.delete()

    async def test_refresh_before_access_expiry_rejected(self, default_guard, mock_users):
        """
        OWASP A01 - Broken Access Control: premature token refresh.

        Verifies that calling ``refresh_token`` on a still-valid access token
        raises :class:`~sanic_beskar.exceptions.EarlyRefreshError`, preventing
        indefinite token extension by repeatedly refreshing before expiry.
        """
        the_dude = await mock_users(username="the_dude")
        with plummet.frozen_time("2017-05-24 10:38:45"):
            token = await default_guard.encode_token(the_dude)

        with plummet.frozen_time("2017-05-24 10:38:46"):
            with pytest.raises(EarlyRefreshError):
                await default_guard.refresh_token(token)

        await the_dude.delete()

    async def test_paseto_tampered_payload_rejected(self, default_guard, mock_users):
        """
        OWASP A02 - Cryptographic Failures: PASETO AEAD tampering.

        Verifies that modifying any byte of a PASETO v4.local ciphertext causes
        authentication-tag verification to fail, preventing payload manipulation.
        PASETO's XChaCha20-Poly1305 AEAD ensures ciphertext integrity end-to-end.
        """
        if default_guard.token_provider != "paseto":
            pytest.skip("PASETO AEAD tamper test is PASETO-specific")

        the_dude = await mock_users(username="the_dude")
        with plummet.frozen_time("2017-05-24 10:38:45"):
            token = await default_guard.encode_token(the_dude)

        # PASETO v4.local format: "v4.local.<base64url-ciphertext>"
        parts = token.split(".")
        raw = base64.urlsafe_b64decode(parts[2] + "==")
        tampered = bytearray(raw)
        tampered[4] ^= 0xFF  # flip a byte deep in the ciphertext
        tampered_b64 = base64.urlsafe_b64encode(bytes(tampered)).rstrip(b"=").decode()
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_b64}"

        with pytest.raises(Exception):
            await default_guard.extract_token(tampered_token)

        await the_dude.delete()

    async def test_paseto_wrong_key_rejected(self, default_guard):
        """
        OWASP A02 - Cryptographic Failures: PASETO wrong-key forgery.

        Verifies that a PASETO token encrypted with a different symmetric key
        is rejected, preventing an attacker who knows the PASETO format but
        not the server secret from forging tokens with arbitrary payloads.
        """
        if default_guard.token_provider != "paseto":
            pytest.skip("PASETO wrong-key test is PASETO-specific")

        import ujson

        wrong_key = PasetoKey.new(version=4, purpose="local", key=b"w" * 32)
        ctx = PasetoLib(exp=900)
        bad_token = ctx.encode(
            wrong_key,
            {"id": "1", "jti": "forged", "rls": "admin"},
            serializer=ujson,
            exp=900,
        ).decode("utf-8")

        with pytest.raises(Exception):
            await default_guard.extract_token(bad_token)

    async def test_lockout_policy_zero_warns(self, default_guard):
        """
        OWASP A05 - Security Misconfiguration: disabled attempt lockout.

        Verifies that setting ``attempt_lockout`` to zero in the password
        policy causes :meth:`~sanic_beskar.Beskar.audit` to emit a
        :class:`UserWarning`, making the insecure configuration visible
        rather than silently allowing unlimited brute-force attempts.
        """
        original_policy = default_guard.password_policy
        try:
            default_guard.password_policy = {**original_policy, "attempt_lockout": 0}
            with pytest.warns(UserWarning, match="attempt_lockout"):
                default_guard.audit()
        finally:
            default_guard.password_policy = original_policy

    async def test_password_not_stored_plaintext(self, default_guard):
        """
        OWASP A02 - Cryptographic Failures: plaintext password storage.

        Verifies that ``hash_password`` never returns the original plaintext
        and that the resulting value carries a recognisable passlib hash prefix,
        providing a baseline sanity check that the hashing pipeline is active.
        """
        plaintext = "super_secret_password"
        hashed = default_guard.hash_password(plaintext)

        assert hashed != plaintext
        assert "$" in hashed

    async def test_rbac_unknown_role_grants_no_right(self, default_guard, mock_users, client):
        """
        OWASP A01 - Broken Access Control: undefined role bypassing RBAC.

        Verifies that a user whose role does not appear in ``rbac_definitions``
        at all is denied access to a rights-protected endpoint, confirming that
        unlisted roles receive no implicit entitlements.
        """
        ghost = await mock_users(username="ghost", roles="completely_unknown_role")
        with plummet.frozen_time("2017-05-24 10:38:45"):
            _, response = await client.get(
                "/rbac_protected",
                headers=await default_guard.pack_header_for_user(ghost),
            )
        assert response.status == 403
        await ghost.delete()
