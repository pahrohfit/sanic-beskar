.. image::  https://badge.fury.io/py/sanic-praetorian.svg
   :target: https://badge.fury.io/py/sanic-praetorian
   :alt:    Latest Published Version

.. image::  https://travis-ci.org/pahrohfit/sanic-praetorian.svg?branch=master
   :target: https://travis-ci.org/pahrohfit/sanic-praetorian
   :alt:    Build Status

.. image::  https://readthedocs.org/projects/sanic-praetorian/badge/?version=latest
   :target: http://sanic-praetorian.readthedocs.io/en/latest/?badge=latest
   :alt:    Documentation Build Status

******************
 sanic-praetorian
******************


** WORK IN PROGRESS -- docs below are mostly correct, I think **

* Probably Stable branch: master
* Working example(s): `examples/*.py`

---------------------------------------------------
Strong, Simple, and Precise security for Sanic APIs
---------------------------------------------------

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
needs of all users, *sanic-praetorian* will provide a simple and secure mechanism
to provide security for APIs specifically.

This project was heavily liftef from the awesome `Flask-Praetorian`.

This extesion offers a batteries-included approach to security for your API.
For essential security concerns for Sanic-based APIs,
`sanic-praetorian <https://github.com/pahrohfit/sanic-praetorian>`_ should
supply everything you need.

The *sanic-praetorian* package can be used to:

* Hash passwords for storing in your database
* Verify plaintext passwords against the hashed, stored versions
* Generate authorization tokens upon verification of passwords
* Check requests to secured endpoints for authorized tokens
* Supply expiration of tokens and mechanisms for refreshing them
* Ensure that the users associated with tokens have necessary roles for access
* Parse user information from request headers for use in client route handlers
* Support inclusion of custom user claims in tokens
* Register new users using email verification

All of this is provided in a very simple to configure and initialize flask
extension. Though simple, the security provided by *sanic-praetorian* is strong
due to the usage of the proven security technology of PASETO or JWT, along with
python's `PassLib <http://pythonhosted.org/passlib/>`_ package.

Super-quick Start
-----------------
 - requirements: `python` versions 3.7+
 - install through pip: `$ pip install sanic-praetorian`
 - minimal usage example: `example/basic.py <https://github.com/pahrohfit/sanic-praetorian/tree/master/example/basic.py>`_

Documentation
-------------

The complete documentation can be found at the
`sanic-praetorian home page <http://sanic-praetorian.readthedocs.io>`_


.. image:: https://api.codacy.com/project/badge/Grade/55f9192c1f584ae294bc1642b0fcc70c
   :alt: Codacy Badge
   :target: https://app.codacy.com/gh/pahrohfit/sanic-beskar?utm_source=github.com&utm_medium=referral&utm_content=pahrohfit/sanic-beskar&utm_campaign=Badge_Grade_Settings