from bson.objectid import ObjectId

from umongo.exceptions import NotCreatedError


class UmongoUserMixin():
    """
    A short-cut providing required methods and attributes for a user class
    implemented with Umongo+Motor(async). Makes many assumptions about how the class
    is defined.

    ASSUMPTIONS:
    * The model has an ``id`` column that uniquely identifies each instance
    * The model has a ``rolenames`` column that contains the roles for the
    user instance as a comma separated list of roles
    * The model has a ``username`` column that is a unique string for each instance
    * The model has a ``password`` column that contains its hashed password

    """

    @property
    def rolenames(self):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class has a :py:meth:``rolenames``
        instance attribute or property that provides a list of strings that
        describe the roles attached to the user instance.

        This can be a seperate table (probably sane), so long as this attribute
        or property properly returns the associated values for the user as a
        list of strings.
        """
        try:
            return self.roles.split(",")
        except Exception:
            return []

    @classmethod
    async def lookup(cls, username=None, email=None):
        """
        *Required Method*

        sanic-praetorian requires that the user class implements a :py:meth:``lookup()``
        class method that takes a single ``username`` or ``email`` argument and
        returns a user instance if there is one that matches or ``None`` if
        there is not.
        """
        try:
            if username:
                return await cls.find_one({'username': username})
            elif email:
                return await cls.find_one({'email': email})
            else:
                return None
        except NotCreatedError:
            return None

    @classmethod
    async def identify(cls, id):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class implements an :py:meth:``identify()``
        class method that takes a single ``id`` argument and returns user instance if
        there is one that matches or ``None`` if there is not.
        """
        try:
            return await cls.find_one({'id': ObjectId(id)})
        except NotCreatedError:
            return None

    @property
    def identity(self):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class has an :py:meth:``identity``
        instance attribute or property that provides the unique id of the user
        instance
        
        Mongo's `id`, by default, is an ObjectId, which cannot be serialized by
        default -- so return as as a string value instead!
        """
        return str(self.id)