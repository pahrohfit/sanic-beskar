Overview
========

API security should be strong, simple, and precise like a Roman Legionary.
This package aims to provide that. Using token implemented by either
`PySETO <https://pyseto.readthedocs.io/en/latest/>`_ or
`PyJWT <https://pyjwt.readthedocs.io/en/latest/>`_,
*flask_praetorian* uses a very simple interface to make sure that the users
accessing your API's endpoints are provisioned with the correct roles for
access.

This project was heavily influenced by
`Flask-Security <https://pythonhosted.org/Flask-Security/>`_, but intends
to supply only essential functionality. Instead of trying to anticipate the
needs of all users, *flask-praetorian* will provide a simple and secure mechanism
to provide security for APIs specifically.

This fork was based on `Flask-Praetorian <https://github.com/dusktreader/flask-praetorian>`_
v.1.3.0, and has been ported to Sanic, because we all want to *go fast*. In
addition to all of the `flask-praetorian` goodness, we've added asyncronous
support, as well as dual factor authentication. All intentions and efforts will
be spared to backport anything from the main `flask-praetorian` code into this fork.

This extesion offers a batteries-included approach to security for your API.
For essential security concerns for `Sanic <https://sanic.dev>`_-based APIs,
`sanic-praetorian <https://github.com/pahrohfit/sanic-praetorian>`_ should
supply everything you need.

The *sanic-praetorian* package can be used to:

* Hash passwords for storing in your database
* Verify plaintext passwords against the hashed, stored versions
* Generate authorization tokens upon verification of passwords
* Check requests to secured endpoints for authorized tokens
* Supply expiration of tokens and mechanisms for refreshing them
* Ensure that the users associated with tokens have necessary roles for access
* Parse user information from request headers or cookies for use in client route handlers
* Support inclusion of custom user claims in tokens
* Register new users using email verification
* Support optional two factor authentication

All of this is provided in a very simple to configure and initialize flask
extension. Though simple, the security provided by *sanic-praetorian* is strong
due to the usage of the proven security technology of PASETO or JWT, along with
python's `PassLib <http://pythonhosted.org/passlib/>`_ package.
