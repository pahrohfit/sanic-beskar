import secrets
import string

import sanic_beskar
from async_sender import Mail  # type: ignore
from sanic import Sanic, json
from sanic_beskar import Beskar
from tortoise import fields
from tortoise.contrib.sanic import register_tortoise
from tortoise.exceptions import DoesNotExist
from tortoise.models import Model

_guard = Beskar()
_mail = Mail()


# A generic user model that might be used by an app powered by sanic-beskar
class User(Model):
    """
    Provides a basic user model for use in the tests
    """

    class Meta:
        table = "User"

    id = fields.IntField(pk=True)
    username = fields.CharField(unique=True, max_length=255)
    password = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255, unique=True)
    roles = fields.CharField(max_length=255, default="")
    is_active = fields.BooleanField(default=True)

    def __str__(self):
        """repr"""
        return f"User {self.id}: {self.username}"

    @property
    def rolenames(self):
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has a :py:meth:``rolenames``
        instance attribute or property that provides a list of strings that
        describe the roles attached to the user instance.

        This can be a separate table (probably sane), so long as this attribute
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

        sanic-beskaruires that the user class implements a :py:meth:``lookup()``
        class method that takes a single ``username`` or ``email`` argument and
        returns a user instance if there is one that matches or ``None`` if
        there is not.
        """
        try:
            if username:
                return await cls.filter(username=username).get()
            elif email:
                return await cls.filter(email=email).get()
            else:
                return None
        except DoesNotExist:
            return None

    @classmethod
    async def identify(cls, id):
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class implements an :py:meth:``identify()``
        class method that takes a single ``id`` argument and returns user instance if
        there is one that matches or ``None`` if there is not.
        """
        try:
            return await cls.filter(id=id).get()
        except DoesNotExist:
            return None

    @property
    def identity(self):
        """
        *Required Attribute or Property*

        sanic-beskar requires that the user class has an :py:meth:``identity``
        instance attribute or property that provides the unique id of the user
        instance
        """
        return self.id


def create_app() -> Sanic:
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic("sanic-testing")
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    # sanic-beskar config
    sanic_app.config.SECRET_KEY = "".join(secrets.choice(string.ascii_letters) for i in range(15))
    sanic_app.config["TOKEN_ACCESS_LIFESPAN"] = {"hours": 1000}
    sanic_app.config["TOKEN_REFRESH_LIFESPAN"] = {"days": 1000}
    sanic_app.config.TOKEN_PLACES = ["header", "cookie"]

    blacklist = set()

    def is_blacklisted(jti) -> bool:
        """return True if the jti is blacklisted"""
        return jti in blacklist

    _guard.init_app(sanic_app, User, is_blacklisted=is_blacklisted)
    sanic_app.ctx.mail = _mail

    register_tortoise(
        sanic_app,
        db_url="sqlite://:memory:",
        modules={"models": ["__main__"]},
        generate_schemas=True,
    )

    # Add users for the example
    @sanic_app.listener("before_server_start")
    async def populate_db(*args):
        """Create a bunch of test users for examples"""
        await User.create(
            username="the_dude",
            email="the_dude@beskar.test.io",
            password=_guard.hash_password("abides"),
            roles="admin",
        )

        await User.create(
            username="Donnie",
            email="donnie@beskar.test.io",
            password=_guard.hash_password("iamthewalrus"),
            roles="operator",
        )

    # Set up some routes for the example
    @sanic_app.route("/login", methods=["POST"])
    async def login(request):
        """
        Logs a user in by parsing a POST request containing user credentials and
        issuing a token.
        .. example::
           $ curl localhost:8000/login -X POST \
             -d '{"username":"Walter","password":"calmerthanyouare"}'
        """
        req = request.json
        username = req.get("username", None)
        password = req.get("password", None)
        user = await _guard.authenticate(username, password)
        ret = {"access_token": await _guard.encode_token(user)}
        return json(ret, status=200)

    @sanic_app.route("/protected")
    @sanic_beskar.auth_required
    async def protected(*args):
        """
        A protected endpoint. The auth_required decorator will require a header
        containing a valid token
        .. example::
           $ curl localhost:8000/protected -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"protected endpoint (allowed user {user.username})"})

    @sanic_app.route("/blacklist_token", methods=["POST"])
    @sanic_beskar.auth_required
    @sanic_beskar.roles_required(["admin"])
    async def blacklist_token(request):
        """
        Blacklists an existing token by registering its jti claim in the blacklist.
        .. example::
           $ curl localhost:5000/blacklist_token -X POST \
             -d '{"token":"<your_token>"}'
        """
        req = request.json
        data = await _guard.extract_token(req["token"])
        blacklist.add(data["jti"])
        return json({"message": f"token blacklisted ({req['token']})"})

    return sanic_app


app = create_app()

# Run the example
if __name__ == "__main__":
    """entry point"""
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
