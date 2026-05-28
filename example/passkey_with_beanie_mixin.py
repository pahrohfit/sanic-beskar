"""
Passkey (WebAuthn) example using sanic-beskar with the BeanieUserMixin.

This example demonstrates the full two-round-trip WebAuthn flow:

  Registration
  ------------
  1. POST /passkey/register/begin   – client requests credential creation options
  2. POST /passkey/register/complete – client returns signed attestation; credential
                                       is stored on the user document

  Authentication
  --------------
  3. POST /passkey/authenticate/begin    – client requests assertion options
  4. POST /passkey/authenticate/complete – client returns signed assertion; a
                                           sanic-beskar JWT is returned on success

  Protected routes work exactly as in the password-based flow:
  5. GET /protected – requires a valid Bearer token

Typical curl flow
-----------------
  # Step 1
  curl -s localhost:8000/passkey/register/begin \\
       -X POST -H "Content-Type: application/json" \\
       -d '{"username": "the_dude"}' | jq .

  # Step 2 (paste the attestation returned by your WebAuthn client)
  curl -s localhost:8000/passkey/register/complete \\
       -X POST -H "Content-Type: application/json" \\
       -d '{"username": "the_dude", "credential": <attestation_json>}'

  # Step 3
  curl -s localhost:8000/passkey/authenticate/begin \\
       -X POST -H "Content-Type: application/json" \\
       -d '{"username": "the_dude"}' | jq .

  # Step 4
  curl -s localhost:8000/passkey/authenticate/complete \\
       -X POST -H "Content-Type: application/json" \\
       -d '{"username": "the_dude", "credential": <assertion_json>}'

  # Step 5
  curl localhost:8000/protected -H "Authorization: Bearer <token>"

Challenge storage
-----------------
This example uses a simple in-process dict for challenge persistence.  In
production replace it with Redis, Memcached, or any async key-value store with
TTL support — see the `store_challenge` / `get_challenge` functions below.
"""

import secrets
import string
from typing import Any, Optional

import sanic_beskar
from beanie import Indexed, init_beanie
from mongomock_motor import AsyncMongoMockClient
from pydantic import Field
from sanic import Sanic, json
from sanic_beskar import Beskar
from sanic_beskar.exceptions import PasskeyChallengeError, PasskeyError, PasskeyVerificationError
from sanic_beskar.orm import BeanieUserMixin

_guard = Beskar()

# ---------------------------------------------------------------------------
# In-memory challenge store (replace with Redis in production)
# ---------------------------------------------------------------------------

_challenge_store: dict[str, bytes] = {}


async def store_challenge(user_id: str, challenge: bytes, ttl: int) -> None:
    """Persist a WebAuthn challenge keyed by user identity."""
    _challenge_store[user_id] = challenge


async def get_challenge(user_id: str) -> bytes | None:
    """Retrieve and consume a stored challenge (one-time use)."""
    return _challenge_store.pop(user_id, None)


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------


class User(BeanieUserMixin):
    """
    User model with Passkey support.

    ``webauthn_credentials`` is inherited from BeanieUserMixin and stores a
    list of registered credential dicts, each containing::

        {
            "id":          "<base64url credential ID>",
            "public_key":  "<base64url COSE public key>",
            "sign_count":  <int>,
            "transports":  ["internal", ...],
        }
    """

    username: str = Indexed(str, unique=True)
    email: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    roles: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)

    def __str__(self) -> str:
        """repr"""
        return f"User {self.id}: {self.username}"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> Sanic:
    """
    Build and return the Sanic application.
    """
    sanic_app = Sanic("sanic-passkey-example")
    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    sanic_app.config.SECRET_KEY = "".join(secrets.choice(string.ascii_letters) for _ in range(32))
    sanic_app.config["TOKEN_ACCESS_LIFESPAN"] = {"hours": 24}
    sanic_app.config["TOKEN_REFRESH_LIFESPAN"] = {"days": 30}

    # WebAuthn relying-party config — set these to match your actual domain
    sanic_app.config["BESKAR_WEBAUTHN_RP_ID"] = "localhost"
    sanic_app.config["BESKAR_WEBAUTHN_RP_NAME"] = "sanic-beskar Passkey Example"
    sanic_app.config["BESKAR_WEBAUTHN_ORIGIN"] = "http://localhost:8000"
    sanic_app.config["BESKAR_WEBAUTHN_CHALLENGE_TTL"] = 120  # seconds

    _guard.init_app(
        sanic_app,
        User,
        webauthn_store_challenge=store_challenge,
        webauthn_get_challenge=get_challenge,
    )

    client: Any = AsyncMongoMockClient()["passkey_example"]

    @sanic_app.listener("before_server_start")
    async def beanie_launch(*_kwargs):
        """Set up Beanie before the first request."""
        await init_beanie(database=client, document_models=[User])

    @sanic_app.listener("before_server_start")
    async def populate_db(*_kwargs):
        """Seed a user who has no password — they will authenticate purely via Passkey."""
        await User(username="the_dude", email="the_dude@example.com").save()

    # -----------------------------------------------------------------------
    # Registration endpoints
    # -----------------------------------------------------------------------

    @sanic_app.route("/passkey/register/begin", methods=["POST"])
    async def passkey_register_begin(request):
        """
        Step 1 of registration.  Returns a ``PublicKeyCredentialCreationOptions``
        dict that the browser's ``navigator.credentials.create()`` call expects.

        Request body::

            {"username": "the_dude"}

        Response (pass to WebAuthn client as-is)::

            {"publicKey": {...}}
        """
        username = (request.json or {}).get("username")
        if not username:
            return json({"error": "username required"}, status=400)

        user = await User.lookup(username=username)
        if not user:
            return json({"error": "user not found"}, status=404)

        options = await _guard.webauthn_generate_registration_options(user)
        return json({"publicKey": options})

    @sanic_app.route("/passkey/register/complete", methods=["POST"])
    async def passkey_register_complete(request):
        """
        Step 2 of registration.  Verifies the attestation returned by the
        browser, stores the new credential on the user, and confirms success.

        Request body::

            {
                "username":   "the_dude",
                "credential": <JSON string from navigator.credentials.create()>
            }
        """
        body = request.json or {}
        username = body.get("username")
        credential_json = body.get("credential")

        if not username or not credential_json:
            return json({"error": "username and credential required"}, status=400)

        user = await User.lookup(username=username)
        if not user:
            return json({"error": "user not found"}, status=404)

        try:
            new_cred = await _guard.webauthn_verify_registration_response(
                user,
                credential_json if isinstance(credential_json, str) else str(credential_json),
            )
        except PasskeyChallengeError as exc:
            return json({"error": str(exc)}, status=400)
        except PasskeyVerificationError as exc:
            return json({"error": str(exc)}, status=400)

        user.webauthn_credentials.append(new_cred)
        await user.save()

        return json({"message": "passkey registered", "credential_id": new_cred["id"]})

    # -----------------------------------------------------------------------
    # Authentication endpoints
    # -----------------------------------------------------------------------

    @sanic_app.route("/passkey/authenticate/begin", methods=["POST"])
    async def passkey_authenticate_begin(request):
        """
        Step 3 of authentication.  Returns a ``PublicKeyCredentialRequestOptions``
        dict that the browser's ``navigator.credentials.get()`` call expects.

        Request body::

            {"username": "the_dude"}
        """
        username = (request.json or {}).get("username")
        if not username:
            return json({"error": "username required"}, status=400)

        user = await User.lookup(username=username)
        if not user:
            return json({"error": "user not found"}, status=404)

        try:
            options = await _guard.webauthn_generate_authentication_options(user)
        except PasskeyError as exc:
            return json({"error": str(exc)}, status=400)

        return json({"publicKey": options})

    @sanic_app.route("/passkey/authenticate/complete", methods=["POST"])
    async def passkey_authenticate_complete(request):
        """
        Step 4 of authentication.  Verifies the assertion, updates the sign
        count, persists the user, and returns a sanic-beskar access token.

        Request body::

            {
                "username":   "the_dude",
                "credential": <JSON string from navigator.credentials.get()>
            }

        Response::

            {"access_token": "<JWT>"}
        """
        body = request.json or {}
        username = body.get("username")
        credential_json = body.get("credential")

        if not username or not credential_json:
            return json({"error": "username and credential required"}, status=400)

        user = await User.lookup(username=username)
        if not user:
            return json({"error": "user not found"}, status=404)

        try:
            user = await _guard.webauthn_verify_authentication_response(
                user,
                credential_json if isinstance(credential_json, str) else str(credential_json),
            )
        except PasskeyChallengeError as exc:
            return json({"error": str(exc)}, status=400)
        except PasskeyVerificationError as exc:
            return json({"error": str(exc)}, status=401)

        # Persist the updated sign count so clone detection stays accurate
        await user.save()

        access_token = await _guard.encode_token(user)
        return json({"access_token": access_token})

    # -----------------------------------------------------------------------
    # Protected routes (identical to the password-based flow)
    # -----------------------------------------------------------------------

    @sanic_app.route("/protected")
    @sanic_beskar.auth_required
    async def protected(request):
        """
        A protected endpoint; requires a valid Bearer token obtained from
        ``/passkey/authenticate/complete``.

        .. example::
           $ curl localhost:8000/protected -H "Authorization: Bearer <token>"
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"protected endpoint (user: {user.username})"})

    @sanic_app.route("/protected_admin_required")
    @sanic_beskar.roles_required(["admin"])
    async def protected_admin_required(request):
        """
        Protected endpoint that requires the ``admin`` role.
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"admin endpoint (user: {user.username})"})

    return sanic_app


app = create_app()

if __name__ == "__main__":
    """entry point"""
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
