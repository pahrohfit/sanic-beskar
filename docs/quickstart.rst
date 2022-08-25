Quickstart
==========

Requirements
------------

* Python 3.7+
* Sanic 22.6+
* Sanic-Ext 22.6+ `provides CORS`
* cryptography 37+ `for encrypting stuff`
* Any `async` Mail plugin, providing :py:func:`mail()` and :py:class:`Mailer()`,
  similiar to `async-sender <https://github.com/theruziev/async_sender>`_

Note on Requirements
....................
Older versions of `Sanic <https://sanic.dev>`_ may work, but are not supported. Stay current.

The examples mainly utilize `Tortoise-ORM <https://tortoise.github.io>`_, a couple also show support
`uMongo <https://github.com/Scille/umongo/blob/master/docs/index.rst>`_, but neither are
required, or even installed by default (except if you install from poetry with the `-D` flag).
Any `async` ORM can be utilized.

Optional Requirements
---------------------

If you would like to generate TOTP QR codes, you will also need to install `segno`::
  pip install segno

If you would like your PBKDF2 hashing to be quick, you should *really* install `fastpbkdf2`::
  pip install fastpbkdf2

Installation
------------

.. note::

    sanic-beskar does not support distutils or setuptools because the
    origional author, as well as this maintainer, have very strong feelings
    about python packaging and the role pip plays in taking us into a bright
    new future of standardized and usable python packaging

Install from pypi
.........................................
This will install the latest release of sanic-beskar from pypi via pip::

$ pip install sanic-beskar

Install latest version from github
..................................
If you would like a version other than the latest published on pypi, you may
do so by cloning the git repository::

$ git clone https://github.com/pahrohfit/sanic-beskar.git

Next, checkout the branch or tag that you wish to use::

$ cd sanic-beskar
$ git checkout master

Finally, use `poetry <https://python-poetry.org>`_ to install from the local directory::

$ poetry install

Example
-------

Several simple examples of :py:mod:`sanic_beskar` doing various aspects of the software
can be found in the `example/ <https://github.com/pahrohfit/sanic-beskar/tree/master/example>`_
directory:

.. list-table:: Sanic-Beskar Examples
   :widths: auto
   :header-rows: 1

   * - File Name
     - Description
   * - `examples/basic.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/basic.py>`_
     - Simple example of most basic usage (see below)
   * - `examples/basic_with_tortoise_mixin.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/basic_with_tortoise_mixin.py>`_
     - Same simple example, using the provided
       :py:mod:`~sanic_beskar.orm.umongo_user_mixins`
   * - `examples/basic_with_umongo_mixin.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/basic_with_umongo_mixin.py>`_
     - Same simple example, using the provided
       :py:mod:`~sanic_beskar.orm.tortoise_user_mixins`
   * - `examples/basic_with_beanie_mixin.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/basic_with_beanie_mixin.py>`_
     - Same simple example, using the provided
       :py:mod:`~sanic_beskar.orm.beanie_user_mixins`
   * - `examples/blacklist.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/blacklist.py>`_
     - Simple example utilizing the blacklist functionality
   * - `examples/custom_claims.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/custom_claims.py>`_
     - Simple example utilizing custom claims in the token
   * - `examples/refresh.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/refresh.py>`_
     - Simple example showing token expirataion and refresh
   * - `examples/register.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/register.py>`_
     - Simple example showing email based registration validation
   * - `examples/basic_with_rbac.py
       <https://github.com/pahrohfit/sanic-beskar/blob/master/example/basic_with_rbac.py>`_
     - Simple example showing RBAC based usage and ``rbac_populate_hook``


The most basic utilization of the :py:mod:`sanic_beskar` decorators is included:

.. literalinclude:: ../example/basic.py
   :language: python
