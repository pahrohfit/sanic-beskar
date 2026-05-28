from typing import Optional

from beanie import Document
from bson.objectid import ObjectId
from pydantic import Field


class BeanieUserMixin(Document):
    """
    A short-cut providing required methods and attributes for a user class
    implemented with `tortoise-orm <https://tortoise.github.io/>`_. Makes
    many assumptions about how the class is defined.

    ASSUMPTIONS:

    * The model has an ``id`` column that uniquely identifies each instance
    * The model has a ``roles`` column that contains the roles for the
      user instance as a comma separated list of roles
    * The model has a ``username`` column that is a unique string for each instance
    * The model has a ``password`` column that contains its hashed password

    The ``webauthn_credentials`` list field is provided by this mixin with an empty
    default. Each entry is a dict with keys: ``id`` (base64url str), ``public_key``
    (base64url str), ``sign_count`` (int), ``transports`` (list[str]).
    """

    webauthn_credentials: list = Field(default_factory=list)

    @property
    def identity(self) -> str:
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has an :py:meth:`identity`
        instance attribute or property that provides the unique id of the user
        instance

        :returns: Provided :py:class:`User.id`
        :rtype: str
        """
        return str(self.id)

    @property
    def rolenames(self) -> list:
        """
        *Required Attribute or Property*

        sanic-beskaruires that the user class has a
        :py:attr:`rolenames` instance attribute or property that
        provides a list of strings that describe the roles attached to
        the user instance.

        This can be a separate table (probably sane), so long as this attribute
        or property properly returns the associated values for the user as a
        RBAC dict, as:
        {'rolename', ['permissions'],}

        :returns: Provided :py:class:`User`'s current ``roles``
        :rtype: list
        """

        _roles: list = self.roles.split(",") if self.roles else []
        return _roles

    @classmethod
    async def lookup(cls, username: str | None = None, email: str | None = None) -> Document | None:
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
        :rtype: :py:class:`User`
        """
        if username:
            return await cls.find({"username": username}).first_or_none()
        if email:
            return await cls.find({"email": email}).first_or_none()

        return None

    @classmethod
    async def identify(cls, id: str) -> Document | None:
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
        return await cls.find({"_id": ObjectId(id)}).first_or_none()

    def get_webauthn_credential(self, credential_id_b64: str) -> dict | None:
        """
        Return the stored credential dict whose ``id`` matches ``credential_id_b64``,
        or ``None`` if no such credential exists on this user.

        :param credential_id_b64: Base64url-encoded credential ID to search for
        :type credential_id_b64: str
        :returns: Matching credential dict, or ``None``
        :rtype: dict | None
        """
        for cred in self.webauthn_credentials:
            if cred.get("id") == credential_id_b64:
                return cred
        return None

    @classmethod
    async def find_by_webauthn_credential_id(
        cls, credential_id_b64: str
    ) -> tuple[Optional["BeanieUserMixin"], dict | None]:
        """
        Return ``(user, credential)`` for the user that owns ``credential_id_b64``,
        or ``(None, None)`` if no user has that credential registered.

        :param credential_id_b64: Base64url-encoded credential ID to search for
        :type credential_id_b64: str
        :returns: Tuple of (user, credential dict) or (None, None)
        :rtype: tuple
        """
        user = await cls.find_one({"webauthn_credentials.id": credential_id_b64})
        if not user:
            return None, None
        return user, user.get_webauthn_credential(credential_id_b64)
