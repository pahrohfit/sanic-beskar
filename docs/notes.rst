Notes
=====

Refreshing Tokens
-----------------

One of the keys to proper security with auth tokens is to make sure that they only last
a finite amont of time. This makes sure that if the token is stolen, it cannot be used
in perpetuity to gain complete access to the user. However, calls to the database to
validate a user on every http request would dramatically slow down an application.

To mitigate both situations, the concept of token refreshing has been introduced. The
idea is that the user is re-checked periodically, but not on every request. After some
fixed amount of time, the database is re-checked to make sure that a user is still
allowed access.

At that point in time, a new token is issued with the same claims as the first except
its refresh lifespan is not extened. This is so that a token cannot be refreshed in
perpetuity.

Once a token's access lifespan and refresh lifespan are both expired, the user must
log in again.

Rate Limiting
-------------

There is not any sort of rate-limiting protection offered by sanic-praetorian.
Thus, if your app does not implment such a thing, it could be vulnerable to brute
force attacks. It's advisable that you implement some sort of system for limiting
incorrect username/password attempts.

Error Handling
--------------

By default, sanic-praetorian will add an error handler to Sanic for
PraetorianErrors. This error handler produces nicely formatted json responses
with status codes that reflect the failures. The sanic-praetorian package's
custom exception type ``PraetorianError`` derives from the ``pyBuzz`` base
exception type from the
`py-buzz exceptions package <https://github.com/dusktreader/py-buzz>`_.
The py-buzz package provides convenience methods for error handlers.

The error handling may be disabled by adding a configuration setting for
``DISABLE_PRAETORIAN_ERROR_HANDLER``. You may wish to do this if you want to
customize your error handling even further.

For example, you may wish to have the error handler log messages about failures
prior to returning an error response. In this case, you can still take
advantage of py-buzz's features to do so:

Configuration Settings
----------------------

.. list-table:: Core Configuration Settings
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``SECRET_KEY``
     - A secret string value used to salt encryptions and hashes for the app.

       ABSOLUTELY MUST BE SET TO SOMETHING OTHER THAN DEFAULT IN PRODUCTION.
     - DO NOT USE THE DEFAULT IN PRODUCTION
   * - ``PRAETORIAN_HASH_SCHEME``
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
   * - ``JWT_ACCESS_LIFESPAN``
     - The default length of time that a JWT may be used to access a protected
       endpoint. See `the PyJWT docs #usage
       <https://pyjwt.readthedocs.io/en/latest/usage.html#expiration-time-claim-exp>`_
       for more details.
     - ``{'minutes': 15}``
   * - ``JWT_REFRESH_LIFESPAN``
     - The default length of time that a JWT may be refreshed. JWT may also not
       be refreshed if its access lifespan is not expired.
     - ``{'days': 30}``
   * - ``JWT_PLACES``
     - A list of places where JWT will be checked
     - ``['header', 'cookie']``
   * - ``JWT_COOKIE_NAME``
     - The name of the cookie in HTTP requests where the JWT will be found
     - ``'access_token'``
   * - ``JWT_HEADER_NAME``
     - The name of the header in HTTP requests where the JWT will be found
     - ``'Authorization'``
   * - ``JWT_HEADER_TYPE``
     - A string describing the type of the header. Usually 'Bearer' but may be
       customized by the user
     - ``'Bearer'``
   * - ``USER_CLASS_VALIDATION_METHOD``
     - The name of the method on a user instance that should be used to
       validate that the user is active in the system.
     - ``'is_valid'``
   * - ``DISABLE_PRAETORIAN_ERROR_HANDLER``
     - Do not register the Sanic error handler automatically. The user may wish
       to configure the error handler themselves
     - ``None``
   * - ``PRAETORIAN_ROLES_DISABLED``
     - If set, role decorators will not work but rolenames will not be a required field
     - ``None``

.. list-table:: OTP Configuration Settings
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``PRAETORIAN_TOTP_ENFORCE``
     - When supporting OTP, if a user is configured with TOTP information,
       should password authentication *require* TOTP validation before a
       successful response is provided, or leave it up to the application
       code to check and enforce.
     - ``True``
   * - ``PRAETORIAN_TOTP_SECRETS_TYPE``
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
   * - ``PRAETORIAN_TOTP_SECRETS_DATA``
     - The string, wallet, or file path, as defined by the
       ``PRAETORIAN_SECRETS_TYPE`` value.

       If anything other than ``None`` is specified for ``PRAETORIAN_SECRETS_TYPE``,
       a ``None`` or invalid value for this will cause a fault in application
       initialization.
     - ``None``

.. list-table:: Mailer Configuration Settings
   :header-rows: 1
   :widths: auto

   * - Flag
     - Description
     - Default Value
   * - ``PRAETORIAN_RESET_SENDER``
     - Default `From:` address for password reset emails.
     - ``you@whatever.com"``
   * - ``PRAETORIAN_RESET_SUBJECT``
     - Default `Subject:` line for password reset emails.
     - ``"Please confirm your registration"``
   * - ``PRAETORIAN_RESET_TEMPLATE``
     - A `Jinja2 <https://github.com/pallets/jinja>`_ template to
       use for password reset emails. The default value is pointing
       to an included basic template file.
     - ``templates/reset_email.html``
   * - ``PRAETORIAN_CONFIRMATION_SENDER``
     - Default `From:` address for new account confirmation emails.
     - ``you@whatever.com"``
   * - ``PRAETORIAN_CONFIRMATION_SUBJECT``
     - Default `Subject:` line for new account confirmation emails.
     - ``"Password Reset Requested"``
   * - ``PRAETORIAN_CONFIRMATION_TEMPLATE``
     - A `Jinja2 <https://github.com/pallets/jinja>`_ template to
       use for new account confirmation emails. The default value is pointing
       to an included basic template file.
     - ``templates/registration_email.html``

.. _user-class-requirements:

Requirements for the user_class
-------------------------------

The ``user_class`` argument supplied during initialization represents the
class that should be used to check for authorization for decorated routes. The
class itself may be implemented in any way that you see fit. It must, however,
satisfy the following requirements:

* Provide a ``lookup`` class method that:

  * should take a single argument of the name of the user

  * should return an instance of the ``user_class`` or ``None``

* Provide an ``identify`` class method

  * should take a single argument of the unique id of the user

  * should return an instance of the ``user_class`` or ``None``

* Provide a ``rolenames`` instance attribute

  * only applies if roles are not disabled. See ``PRAETORIAN_ROLES_DISABLED`` setting

  * should return a list of string roles assigned to the user

* Provide a ``password`` instance attribute

  * should return the hashed password assigned to the user

* Provide an ``identity`` instance attribute

  * should return the unique id of the user

Although the example given in the documentation uses a SQLAlchemy model for the
userclass, this is not a requirement.
