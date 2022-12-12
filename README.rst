.. image::  https://badge.fury.io/py/sanic-beskar.svg
   :target: https://badge.fury.io/py/sanic-beskar
   :alt:    Latest Published Version

.. image::  https://github.com/pahrohfit/sanic-beskar/actions/workflows/main.yml/badge.svg
   :target: https://github.com/pahrohfit/sanic-beskar/actions/workflows/main.yml
   :alt:    Build Testing Status

.. image::  https://img.shields.io/pypi/pyversions/sanic-beskar.svg
   :target: https://img.shields.io/pypi/pyversions/sanic-beskar
   :alt:    Supported Python versions

.. image::  https://readthedocs.org/projects/sanic-beskar/badge/?version=latest
   :target: http://sanic-beskar.readthedocs.io/en/latest/?badge=latest
   :alt:    Documentation Build Status

.. image::  https://codecov.io/gh/pahrohfit/sanic-beskar/branch/master/graph/badge.svg?token=24WAYX4OMT
   :target: https://codecov.io/gh/pahrohfit/sanic-beskar
   :alt:    Codecov Report

.. image:: https://static.pepy.tech/personalized-badge/sanic-beskar?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads
  :target: https://pepy.tech/project/sanic-beskar

.. image::  https://api.codacy.com/project/badge/Grade/55f9192c1f584ae294bc1642b0fcc70c
   :alt:    Codacy Badge
   :target: https://app.codacy.com/gh/pahrohfit/sanic-beskar?utm_source=github.com&utm_medium=referral&utm_content=pahrohfit/sanic-beskar&utm_campaign=Badge_Grade_Settings

.. image::  https://mayhem4api.forallsecure.com/api/v1/api-target/pahrohfit/pahrohfit-sanic-beskar/badge/icon.svg?scm_branch=master
   :alt:    Mayhem for API
   :target: https://mayhem4api.forallsecure.com/pahrohfit/pahrohfit-sanic-beskar/latest-job?scm_branch=master

.. image::   https://img.shields.io/badge/security-bandit-yellow.svg
    :target: https://github.com/PyCQA/bandit
    :alt:    Security Status

******************
 sanic-beskar
******************

* Stable branch: `master <https://github.com/pahrohfit/sanic-beskar/tree/master/sanic_beskar>`_
* CBTE (coding by trial and error) branch: `dev <https://github.com/pahrohfit/sanic-beskar/tree/dev/sanic_beskar>`_
* Working example(s): `examples/*.py <https://github.com/pahrohfit/sanic-beskar/tree/master/example>`_

---------------------------------------------------
Strong, Simple, and Precise security for Sanic APIs
---------------------------------------------------

This project's begining was fully lifted from the awesome
`Flask-Praetorian <https://github.com/dusktreader/flask-praetorian>`_.

Why `beskar <https://starwars.fandom.com/wiki/Beskar>`_? Why not -- what
is better than star wars (provided you ignore the fact ~the mandolorian~
was almost as lame as ~book of boba fett~)?
Superior armour should be used if you want superior protection.

This package aims to provide that. Using token implemented by either
`PySETO <https://pyseto.readthedocs.io/en/latest/>`_ or
`PyJWT <https://pyjwt.readthedocs.io/en/latest/>`_,
*sanic-beskar* uses a very simple interface to make sure that the users
accessing your API's endpoints are provisioned with the correct roles for
access.

The goal of this project is to offer simplistic protection, without
forcing nonsense, excessivly complicatated implimentation, or
mandated/opinionated ORM usage. Providing this usability for small
scaled Sanic applications, while allowing the flexibility and
scalability for enterprise grade solutions, seperates this from your
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

Super-quick Start
-----------------
 - requirements: `python` versions 3.7+
 - install through pip: `$ pip install sanic-beskar`
 - minimal usage example: `example/basic.py <https://github.com/pahrohfit/sanic-beskar/tree/master/example/basic.py>`_

Documentation
-------------

The complete documentation can be found at the
`sanic-beskar home page <http://sanic-beskar.readthedocs.io>`_
