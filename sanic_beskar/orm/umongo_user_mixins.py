from typing import Optional
from bson.objectid import ObjectId

# umongo is missing type hints at this time
from umongo.exceptions import NotCreatedError # type: ignore
from umongo import Document # type: ignore


class UmongoUserMixin(Document):
    """
    A short-cut providing required methods and attributes for a user class
    implemented with `uMongo <https://github.com/Scille/umongo/blob/master/docs/index.rst>`_
    + `Motor(async) <https://github.com/mongodb/motor/>`_. Makes many assumptions about
    how the class is defined.

    **ASSUMPTIONS**

    * The model has an ``id`` column that uniquely identifies each instance
    * The model has a ``rolenames`` column that contains the roles for the
      user instance as a comma separated list of roles
    * The model has a ``username`` column that is a unique string for each instance
    * The model has a ``password`` column that contains its hashed password
    """

    @property
    def rolenames(self) -> Optional[list]:
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has a
        :py:attr:`rolenames` instance attribute or property that
        provides a list of strings that describe the roles attached to
        the user instance.

        This can be a seperate table (probably sane), so long as this attribute
        or property properly returns the associated values for the user as a
        RBAC dict, as:
        {'rolename', ['permissions'],}

        :returns: Provided :py:class:`User`'s current ``roles``
        :rtype: list
        """
        try:
            return self.roles.split(",") # type: ignore
        except Exception:
            return []

    @classmethod
    async def lookup(cls, username: Optional[str] = None, email: Optional[str] = None) -> Optional[Document]:
        """
        *Required Method*

        sanic-beskar requires that the user class implements a :py:meth:`lookup()`
        class method that takes a single :py:data:`username` or :py:data:`email`
        argument and returns a user instance if there is one that matches or
        ``None`` if there is not.

        :param username: `username` of the user to lookup
        :type username: Optional[str]
        :param email: `email` of the user to lookup
        :type email: Optional[str]

        :returns: ``None`` or :py:class:`User` of the found user
        :rtype: :py:class:`User`, None
        """
        try:
            if username:
                return await cls.find_one({'username': username})
            if email:
                return await cls.find_one({'email': email})
            return None
        except NotCreatedError:
            return None

    @classmethod
    async def identify(cls, id: str) -> Optional[Document]:
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class implements an
        :py:meth:`identify()` class method that takes a single
        :py:data:`id` argument and returns user instance if
        there is one that matches or ``None`` if there is not.

        :param self: a :py:class:`User` object
        :type self: :py:class:`User`

        :returns: Provided :py:class:`User` ``id``
        :rtype: str, None
        """
        try:
            return await cls.find_one({'id': ObjectId(id)})
        except NotCreatedError:
            return None

    @property
    def identity(self) -> str:
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has an :py:meth:`identity`
        instance attribute or property that provides the unique id of the user
        instance

        Mongo's :py:data:`id`, by default, is an :py:func:`~bson.objectid.ObjectId()`,
        which cannot be serialized by default -- so return as as a
        string value instead!

        :returns: Provided :py:class:`User` id
        :rtype: str
        """
        return str(self.id)
