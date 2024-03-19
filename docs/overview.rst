Overview
========

This project's beginning was fully lifted from the awesome
`Flask-Praetorian <https://github.com/dusktreader/flask-praetorian>`_.

Why `beskar <https://starwars.fandom.com/wiki/Beskar>`_? Why not -- what
is better than star wars (provided you ignore the fact *the mandolorian*
was almost as lame as *book of boba fett*)?
Superior armour should be used if you want superior protection.

This package aims to provide that. Using token implemented by either
`PySETO <https://pyseto.readthedocs.io/en/latest/>`_ or
`PyJWT <https://pyjwt.readthedocs.io/en/latest/>`_,
*sanic-beskar* uses a very simple interface to make sure that the users
accessing your API's endpoints are provisioned with the correct roles for
access.

The goal of this project is to offer simplistic protection, without
forcing nonsense, excessivly complicatated implementation, or
mandated/opinionated ORM usage. Providing this usability for small
scaled Sanic applications, while allowing the flexibility and
scalability for enterprise grade solutions, separates this from your
other options.

The *sanic-beskar* package can be used to:

* Hash passwords for storing in your database
* Verify plaintext passwords against the hashed, stored versions
* Generate authorization tokens upon verification of passwords
* Check requests to secured endpoints for authorized tokens
* Supply expiration of tokens and mechanisms for refreshing them
* Ensure that the users associated with tokens have necessary roles for access
* Parse user information from request headers for use in client route handlers
* Support inclusion of custom user claims in tokens
* Register new users using email verification
* Support OTP authentication as a dual factor
* Provide RBAC based protection of endpoints and resources

All of this is provided in a very simple to configure and initialize flask
extension. Though simple, the security provided by *sanic-beskar* is strong
due to the usage of the proven security technology of PASETO or JWT, along with
python's `PassLib <http://pythonhosted.org/passlib/>`_ package.
