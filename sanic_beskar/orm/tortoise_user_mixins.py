from typing import Optional

from bson.objectid import ObjectId
from tortoise.exceptions import DoesNotExist
from tortoise.models import Model


class TortoiseUserMixin(Model):
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

    To use Passkey support, the concrete model must also define::

        import ujson
        from tortoise import fields as tortoise_field

        webauthn_credentials_json = tortoise_field.TextField(default="[]")

        @property
        def webauthn_credentials(self) -> list:
            return ujson.loads(self.webauthn_credentials_json or "[]")

    """

    @property
    def identity(self) -> str | ObjectId:
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has an :py:meth:`identity`
        instance attribute or property that provides the unique id of the user
        instance

        :returns: Provided :py:class:`User.id`
        :rtype: str
        """
        return self.id  # type: ignore

    @property
    def rolenames(self) -> list | None:
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

        _roles: list = self.roles.split(",") if self.roles else []  # type: ignore
        return _roles

    @classmethod
    async def lookup(cls, username: str | None = None, email: str | None = None) -> Model | None:
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
        try:
            if username:
                return await cls.filter(username=username).get()
            if email:
                return await cls.filter(email=email).get()
            return None
        except DoesNotExist:
            return None

    @classmethod
    async def identify(cls, id: ObjectId) -> Model | None:
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
            return await cls.filter(id=id).get()
        except DoesNotExist:
            return None

    def get_webauthn_credential(self, credential_id_b64: str) -> dict | None:
        """
        Return the stored credential dict whose ``id`` matches ``credential_id_b64``,
        or ``None`` if no such credential exists on this user.

        Requires the concrete model to define a ``webauthn_credentials`` property
        backed by a ``webauthn_credentials_json`` TextField.

        :param credential_id_b64: Base64url-encoded credential ID to search for
        :type credential_id_b64: str
        :returns: Matching credential dict, or ``None``
        :rtype: dict | None
        """
        for cred in getattr(self, "webauthn_credentials", []):
            if cred.get("id") == credential_id_b64:
                return cred
        return None

    @classmethod
    async def find_by_webauthn_credential_id(
        cls, credential_id_b64: str
    ) -> tuple[Optional["TortoiseUserMixin"], dict | None]:
        """
        Return ``(user, credential)`` for the user that owns ``credential_id_b64``,
        or ``(None, None)`` if no user has that credential registered.

        Scans all users; for large tables consider a custom implementation with a
        dedicated credentials table or a JSON index.

        :param credential_id_b64: Base64url-encoded credential ID to search for
        :type credential_id_b64: str
        :returns: Tuple of (user, credential dict) or (None, None)
        :rtype: tuple
        """
        for user in await cls.all():
            cred = user.get_webauthn_credential(credential_id_b64)
            if cred:
                return user, cred
        return None, None
