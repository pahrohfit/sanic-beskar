Notes
=====

Refreshing Tokens
-----------------

One of the keys to proper security with auth tokens is to make sure that they only last
a finite amount of time. This makes sure that if the token is stolen, it cannot be used
in perpetuity to gain complete access to the user. However, calls to the database to
validate a user on every http request would dramatically slow down an application.

To mitigate both situations, the concept of token refreshing has been introduced. The
idea is that the user is re-checked periodically, but not on every request. After some
fixed amount of time, the database is re-checked to make sure that a user is still
allowed access.

At that point in time, a new token is issued with the same claims as the first except
its refresh lifespan is not extended. This is so that a token cannot be refreshed in
perpetuity.

Once a token's access lifespan and refresh lifespan are both expired, the user must
log in again.

Rate Limiting
-------------

There is not any sort of rate-limiting protection offered by sanic-beskar.
Thus, if your app does not implement such a thing, it could be vulnerable to brute
force attacks. It's advisable that you implement some sort of system for limiting
incorrect username/password attempts.

Error Handling
--------------

By default, sanic-beskar will add an error handler to Sanic for
BeskarErrors. This error handler produces nicely formatted json responses
with status codes that reflect the failures. The sanic-beskar package's
custom exception type ``BeskarError`` derives from the ``pyBuzz`` base
exception type from the
`py-buzz exceptions package <https://github.com/dusktreader/py-buzz>`_.
The py-buzz package provides convenience methods for error handlers.

The error handling may be disabled by adding a configuration setting for
``DISABLE_BESKAR_ERROR_HANDLER``. You may wish to do this if you want to
customize your error handling even further.

For example, you may wish to have the error handler log messages about failures
prior to returning an error response. In this case, you can still take
advantage of py-buzz's features to do so:

.. _user-class-requirements:

Requirements for the user_class
-------------------------------

The ``user_class`` argument supplied during initialization represents the
class that should be used to check for authorization for decorated routes. The
class itself may be implemented in any way that you see fit. It must, however,
satisfy the following requirements:

* Provide an `async` ``lookup`` class method that:

  * should take a single argument of the name of the user

  * should return an instance of the ``user_class`` or ``None``

* Provide an `async` ``identify`` class method

  * should take a single argument of the unique id of the user

  * should return an instance of the ``user_class`` or ``None``

* Provide an `async` ``rolenames`` instance attribute

  * only applies if roles are not disabled. See ``BESKAR_ROLES_DISABLED`` setting

  * should return a list of string roles assigned to the user

* Provide an `async` ``identity`` instance attribute

  * should return the unique id of the user

Although the example given in the documentation uses a SQLAlchemy model for the
userclass, this is not a requirement.

.. _rbac-populate-hook-requirements:

Requirements for the `rbac_populate_hook`
-----------------------------------------

The optional ``rbac_populate_hook`` argument supplied during initialization represents
the `async` function that should be used to update the RBAC definitions for
the application.

This function, if provided, will be called at ``init_app()`` time to retrieve and load
the RBAC policy for your application, for use in the ``@rights_required()`` decorator.
This is, essentially, a grouping of discrete rights or entitlements, tied back to a role,
providing granular control over routes and resources.

The expected output of this function is a ``dict()``, showing the grouping to use.

.. code-block:: python

  {
   'rolename_1': [
     'access_right_1',
     'access_right_2',
     'access_right_3'
   ],
   'rolename_2': [
     'access_right_2',
     'access_right_4'
   ],
   'rolename_3': [
     'access_right_5',
     'access_right_6'
   ],
  }

Rights can be overlapping (contained in multiple role definitions).

To trigger an update, a call to a Sanic signal ``beskar.rbac.update`` should be sent.
This will cause Sanic-Beskar to re-run the ``rbac_populate_hook`` and update the policy
without needing an application restart. This is most useful for when the policy can be
modified, while the app is running, and pulled from a database::

  await sanic_app.dispatch("beskar.rbac.update")
