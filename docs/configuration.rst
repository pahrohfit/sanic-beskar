Configuration Settings
======================

Core Configuration Settings
---------------------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``SECRET_KEY``
     - A secret string value used to salt encryptions and hashes for the app.

       ABSOLUTELY MUST BE SET TO SOMETHING OTHER THAN DEFAULT IN PRODUCTION.
     - DO NOT USE THE DEFAULT IN PRODUCTION
   * - ``BESKAR_HASH_SCHEME``
     - The hash scheme used to hash passwords in the database. If unset,
       passlib will use the default scheme which is ``pbkdf2_sha512``
     - ``'pbkdf2_sha512'``
   * - ``JWT_ALLOWED_ALGORITHMS``
     - A list of allowed algorithms that may be used to hash the JWT. See `the
       PyJWT docs #algorithms <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
       for more details.
     - ``['HS256']``
   * - ``JWT_ALGORITHM``
     - The jwt hashing algorithm to be used to encode tokens
     - ``'HS256'``
   * - ``TOKEN_ACCESS_LIFESPAN``
     - The default length of time that a token may be used to access a protected
       endpoint. See `the PyJWT docs #usage
       <https://pyjwt.readthedocs.io/en/latest/usage.html#expiration-time-claim-exp>`_
       for more details.
     - ``{'minutes': 15}``
   * - ``TOKEN_REFRESH_LIFESPAN``
     - The default length of time that a token may be refreshed. Token may also not
       be refreshed if its access lifespan is not expired.
     - ``{'days': 30}``
   * - ``TOKEN_PLACES``
     - A list of places where token will be checked
     - ``['header', 'cookie']``
   * - ``TOKEN_COOKIE_NAME``
     - The name of the cookie in HTTP requests where the token will be found
     - ``'access_token'``
   * - ``TOKEN_HEADER_NAME``
     - The name of the header in HTTP requests where the token will be found
     - ``'Authorization'``
   * - ``TOKEN_HEADER_TYPE``
     - A string describing the type of the header. Usually 'Bearer' but may be
       customized by the user
     - ``'Bearer'``
   * - ``USER_CLASS_VALIDATION_METHOD``
     - The name of the method on a user instance that should be used to
       validate that the user is active in the system.
     - ``'is_valid'``
   * - ``DISABLE_BESKAR_ERROR_HANDLER``
     - Do not register the Sanic error handler automatically. The user may wish
       to configure the error handler themselves
     - ``None``
   * - ``BESKAR_ROLES_DISABLED``
     - If set, role decorators will not work but rolenames will not be a required field
     - ``None``

OTP Configuration Settings
--------------------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``BESKAR_TOTP_ENFORCE``
     - When supporting OTP, if a user is configured with TOTP information,
       should password authentication *require* TOTP validation before a
       successful response is provided, or leave it up to the application
       code to check and enforce.
     - ``True``
   * - ``BESKAR_TOTP_SECRETS_TYPE``
     - The type of `secrets` protection for the TOTP implimentation. The
       available options are:

       * ``None`` (default) indicates **no** encryption protection of stored
         TOTP configuration for each user (data will be stored, in clear, in
         your datastore). This is most likely a terrible idea for PRODUCTION
         applications.
       * ``file`` indicates encryption secret material is stored in a file,
         available on the filesystem, at the time of app initialization.
       * ``wallet`` indicates a `passlib.TOTP.AppWallet()
         <https://passlib.readthedocs.io/en/stable/lib/passlib.totp.html#passlib.totp.AppWallet>`_
         is being used.
       * ``string`` indicates the secret material will be provided as a
         JSON string, as defined by `passlib.TOTP.AppWallet()
         <https://passlib.readthedocs.io/en/stable/lib/passlib.totp.html#passlib.totp.AppWallet>`_

       ABSOLUTELY MUST BE SET TO SOMETHING OTHER THAN DEFAULT IN PRODUCTION.
     - DO NOT USE THE DEFAULT ``None`` IN PRODUCTION
   * - ``BESKAR_TOTP_SECRETS_DATA``
     - The string, wallet, or file path, as defined by the
       ``BESKAR_SECRETS_TYPE`` value.

       If anything other than ``None`` is specified for ``BESKAR_SECRETS_TYPE``,
       a ``None`` or invalid value for this will cause a fault in application
       initialization.
     - ``None``

Mailer Configuration Settings
-----------------------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``BESKAR_RESET_SENDER``
     - Default `From:` address for password reset emails.
     - ``you@whatever.com"``
   * - ``BESKAR_RESET_SUBJECT``
     - Default `Subject:` line for password reset emails.
     - ``"Please confirm your registration"``
   * - ``BESKAR_RESET_TEMPLATE``
     - A `Jinja2 <https://github.com/pallets/jinja>`_ template to
       use for password reset emails. The default value is pointing
       to an included basic template file.
     - ``templates/reset_email.html``
   * - ``BESKAR_CONFIRMATION_SENDER``
     - Default `From:` address for new account confirmation emails.
     - ``you@whatever.com"``
   * - ``BESKAR_CONFIRMATION_SUBJECT``
     - Default `Subject:` line for new account confirmation emails.
     - ``"Password Reset Requested"``
   * - ``BESKAR_CONFIRMATION_TEMPLATE``
     - A `Jinja2 <https://github.com/pallets/jinja>`_ template to
       use for new account confirmation emails. The default value is pointing
       to an included basic template file.
     - ``templates/registration_email.html``
