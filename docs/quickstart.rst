Quickstart
==========

Requirements
------------

* Python 3.7+
* Sanic 22.6+
* Sanic-Ext 22.6+ `provides CORS`
* Any `async` Mail plugin, providing :py:func:`mail()` and :py:class:`Mailer()`, 
  similiar to `Sanic-Mailing <https://github.com/pahrohfit/sanic-mailing>`_

Note on Requirements
....................
Older versions of `Sanic <https://sanic.dev>`_ may work, but are not supported. Stay current.

The examples utilize `Tortoise-ORM <https://tortoise.github.io>`_, but it is not required, or even installed
by default (except if you install from poetry with the `-D` flag). Any `async` ORM can be utilized.

Installation
------------

.. note::

    sanic-praetorian does not support distutils or setuptools because the
    origional author, as well as this maintainer, have very strong feelings
    about python packaging and the role pip plays in taking us into a bright
    new future of standardized and usable python packaging

Install from pypi (**coming soon**)
.........................................
This will install the latest release of sanic-praetorian from pypi via pip::

$ pip install sanic-praetorian

Install latest version from github
..................................
If you would like a version other than the latest published on pypi, you may
do so by cloning the git repository::

$ git clone https://github.com/pahrohfit/sanic-praetorian.git

Next, checkout the branch or tag that you wish to use::

$ cd sanic-praetorian
$ git checkout master

Finally, use `poetry <https://python-poetry.org>`_ to install from the local directory::

$ poetry install

Example
-------

A minimal example of how to use the sanic-praetorian decorators is included:

.. literalinclude:: ../example/basic.py
   :language: python

The above code can be found in `example/basic.py
<https://github.com/pahrohfit/sanic-praetorian/blob/master/example/basic.py>`_.
