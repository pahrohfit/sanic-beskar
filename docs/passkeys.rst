Passkeys (WebAuthn)
===================

sanic-beskar supports passwordless authentication via `WebAuthn / Passkeys
<https://webauthn.guide/>`_.  Users register a hardware key, phone, or
platform authenticator once, then sign in with a biometric or PIN instead
of a password.  On success, the usual sanic-beskar JWT is issued, so all
existing ``@auth_required`` and role decorators work without any changes.

Installation
------------

Passkey support ships as an optional extra::

    pip install "sanic-beskar[webauthn]"

The extra installs the `py_webauthn <https://github.com/duo-labs/py_webauthn>`_
library, which does the cryptographic heavy lifting.

How it works
------------

Passkey authentication is a two-round-trip protocol, both for registration
and for authentication.

**Registration** (enrolling a new key)

1. Your server generates a challenge and credential-creation options, then
   sends them to the browser.
2. The browser passes the options to ``navigator.credentials.create()``, the
   user touches their authenticator, and the browser returns a signed
   attestation.
3. Your server verifies the attestation, stores the new credential on the
   user, and confirms success.

**Authentication** (signing in)

1. Your server generates a challenge and credential-request options for the
   user's registered keys, then sends them to the browser.
2. The browser passes the options to ``navigator.credentials.get()``, the
   user touches their authenticator, and the browser returns a signed
   assertion.
3. Your server verifies the assertion, updates the stored sign-count (for
   clone-detection), and issues a JWT.

Challenge storage
-----------------

WebAuthn challenges are short-lived secrets that must survive the
round-trip to the browser (typically a few seconds to a couple of minutes).
sanic-beskar does not dictate how you store them — you supply two async
callables at init time:

* ``webauthn_store_challenge(user_id: str, challenge: bytes, ttl: int) -> None``
* ``webauthn_get_challenge(user_id: str) -> bytes | None``

For local development an in-process ``dict`` is fine.  In production, use
Redis, Memcached, or any key-value store that supports TTL expiry.

.. code-block:: python

    import asyncio
    import redis.asyncio as aioredis

    redis = aioredis.from_url("redis://localhost")

    async def store_challenge(user_id: str, challenge: bytes, ttl: int) -> None:
        await redis.setex(f"wauthn:{user_id}", ttl, challenge)

    async def get_challenge(user_id: str) -> bytes | None:
        value = await redis.getdel(f"wauthn:{user_id}")
        return value  # None if missing or expired

User model requirements
-----------------------

Your user class needs a ``webauthn_credentials`` attribute that stores a list
of credential dicts.  Each dict has the shape::

    {
        "id":          "<base64url credential ID>",
        "public_key":  "<base64url COSE public key>",
        "sign_count":  <int>,
        "transports":  ["internal", ...],
    }

The built-in :py:class:`~sanic_beskar.orm.BeanieUserMixin` already includes
this field.  For Tortoise-ORM, add a ``TextField`` backed property as shown
in the mixin docs.  For any other ORM, add the field yourself — the guard
only reads and writes ``user.webauthn_credentials`` as a plain Python list.

App setup
---------

Pass the challenge callables when initialising the guard:

.. code-block:: python

    from sanic_beskar import Beskar

    guard = Beskar()

    guard.init_app(
        app,
        User,
        webauthn_store_challenge=store_challenge,
        webauthn_get_challenge=get_challenge,
    )

Then configure the relying-party settings to match your domain
(see :doc:`configuration`):

.. code-block:: python

    app.config["BESKAR_WEBAUTHN_RP_ID"]     = "example.com"
    app.config["BESKAR_WEBAUTHN_RP_NAME"]   = "My App"
    app.config["BESKAR_WEBAUTHN_ORIGIN"]    = "https://example.com"
    app.config["BESKAR_WEBAUTHN_CHALLENGE_TTL"] = 120  # seconds

Endpoints
---------

Wire up four routes — two for registration, two for authentication:

.. code-block:: python

    from sanic import json
    from sanic_beskar.exceptions import PasskeyChallengeError, PasskeyVerificationError

    # ── Registration ─────────────────────────────────────────────────────────

    @app.route("/passkey/register/begin", methods=["POST"])
    async def register_begin(request):
        user = await User.lookup(username=request.json["username"])
        options = await guard.webauthn_generate_registration_options(user)
        return json({"publicKey": options})

    @app.route("/passkey/register/complete", methods=["POST"])
    async def register_complete(request):
        user = await User.lookup(username=request.json["username"])
        try:
            cred = await guard.webauthn_verify_registration_response(
                user, request.json["credential"]
            )
        except (PasskeyChallengeError, PasskeyVerificationError) as exc:
            return json({"error": str(exc)}, status=400)

        user.webauthn_credentials.append(cred)
        await user.save()
        return json({"credential_id": cred["id"]})

    # ── Authentication ────────────────────────────────────────────────────────

    @app.route("/passkey/authenticate/begin", methods=["POST"])
    async def auth_begin(request):
        user = await User.lookup(username=request.json["username"])
        options = await guard.webauthn_generate_authentication_options(user)
        return json({"publicKey": options})

    @app.route("/passkey/authenticate/complete", methods=["POST"])
    async def auth_complete(request):
        user = await User.lookup(username=request.json["username"])
        try:
            user = await guard.webauthn_verify_authentication_response(
                user, request.json["credential"]
            )
        except PasskeyChallengeError as exc:
            return json({"error": str(exc)}, status=400)
        except PasskeyVerificationError as exc:
            return json({"error": str(exc)}, status=401)

        await user.save()  # persist updated sign_count
        token = await guard.encode_token(user)
        return json({"access_token": token})

The ``access_token`` from ``auth_complete`` is a standard sanic-beskar JWT.
Use it exactly as you would a password-issued token:

.. code-block:: python

    @app.route("/protected")
    @sanic_beskar.auth_required
    async def protected(request):
        user = await sanic_beskar.current_user()
        return json({"message": f"Hello, {user.username}"})

Full working example
--------------------

A complete runnable example using Beanie (MongoDB) is included in the
repository:

.. list-table::
   :widths: auto
   :header-rows: 1

   * - File
     - Description
   * - `example/passkey_with_beanie_mixin.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/passkey_with_beanie_mixin.py>`_
     - End-to-end Passkey flow with Beanie and an in-memory challenge store

Error handling
--------------

The guard raises three Passkey-specific exceptions, all subclasses of
:py:exc:`~sanic_beskar.exceptions.BeskarError`:

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Exception
     - When raised
   * - :py:exc:`~sanic_beskar.exceptions.PasskeyError`
     - Base class; also raised directly when a user has no registered credentials.
   * - :py:exc:`~sanic_beskar.exceptions.PasskeyChallengeError`
     - The expected challenge is missing, expired, or was already consumed.
   * - :py:exc:`~sanic_beskar.exceptions.PasskeyVerificationError`
     - The cryptographic verification of the attestation or assertion failed.

All three are exported from the top-level ``sanic_beskar`` namespace::

    from sanic_beskar.exceptions import (
        PasskeyError,
        PasskeyChallengeError,
        PasskeyVerificationError,
    )
