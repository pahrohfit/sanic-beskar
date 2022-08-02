import secrets, string

from tortoise.contrib.sanic import register_tortoise
from tortoise.models import Model
from tortoise import fields

from sanic import Sanic, json

import sanic_beskar
from sanic_beskar import Beskar
from sanic_beskar.orm import TortoiseUserMixin

from async_sender import Mail


_guard = Beskar()
_mail = Mail()


# A generic user model that might be used by an app powered by sanic-beskar
class User(Model, TortoiseUserMixin):
    """
    Provides a basic user model for use in the tests
    """

    class Meta:
        table = "User"

    id = fields.IntField(pk=True)
    username = fields.CharField(unique=True, max_length=255)
    password = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255, unique=True)
    roles = fields.CharField(max_length=255, default='')
    is_active = fields.BooleanField(default=True)

    def __str__(self):
        return f"User {self.id}: {self.username}"


def create_app(db_path=None):
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic('sanic-testing')
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    # sanic-beskar config
    sanic_app.config.SECRET_KEY = ''.join(secrets.choice(string.ascii_letters) for i in range(15))
    sanic_app.config["TOKEN_ACCESS_LIFESPAN"] = {"hours": 24}
    sanic_app.config["TOKEN_REFRESH_LIFESPAN"] = {"days": 30}

    _guard.init_app(sanic_app, User)
    sanic_app.ctx.mail = _mail

    register_tortoise(
        sanic_app,
        db_url='sqlite://:memory:',
        modules={"models": ['__main__']},
        generate_schemas=True,
    )

    # Add users for the example
    @sanic_app.listener('before_server_start')
    async def populate_db(sanic):
        await User.create(username="the_dude",
                          email="the_dude@beskar.test.io",
                          password=_guard.hash_password("abides"),)

        await User.create(username="Walter",
                          email="walter@beskar.test.io",
                          password=_guard.hash_password("calmerthanyouare"),
                          roles="admin",)

        await User.create(username="Donnie",
                          email="donnie@beskar.test.io",
                          password=_guard.hash_password("iamthewalrus"),
                          roles="operator",)

        await User.create(username="Maude",
                          password=_guard.hash_password("andthorough"),
                          email="maude@beskar.test.io",
                          roles="operator,admin",)

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
    async def protected(request):
        """
        A protected endpoint. The auth_required decorator will require a header
        containing a valid token
        .. example::
           $ curl localhost:8000/protected -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"protected endpoint (allowed user {user.username})"})

    @sanic_app.route("/protected_admin_required")
    @sanic_beskar.roles_required("admin")
    async def protected_admin_required(request):
        """
        A protected endpoint that requires a role. The roles_required decorator
        will require that the supplied token includes the required roles
        .. example::
           $ curl localhost:8000/protected_admin_required -X GET \
              -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"protected_admin_required endpoint (allowed user {user.username})"})

    @sanic_app.route("/protected_operator_accepted")
    @sanic_beskar.roles_accepted("operator", "admin")
    async def protected_operator_accepted(request):
        """
        A protected endpoint that accepts any of the listed roles. The
        roles_accepted decorator will require that the supplied token includes at
        least one of the accepted roles
        .. example::
           $ curl localhost/protected_operator_accepted -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_beskar.current_user()
        return json({"message": f"protected_operator_accepted endpoint (allowed usr {user.username}"})

    return sanic_app


# Run the example
if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
