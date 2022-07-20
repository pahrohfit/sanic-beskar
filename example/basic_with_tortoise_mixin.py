from tortoise.contrib.sanic import register_tortoise
from tortoise.models import Model
from tortoise import fields
from tortoise.exceptions import DoesNotExist

from sanic import Sanic, json

import sanic_praetorian
from sanic_praetorian import Praetorian
from sanic_praetorian.orm import TortoiseUserMixin

from sanic_mailing import Mail


_guard = Praetorian()
_mail = Mail()


# A generic user model that might be used by an app powered by sanic-praetorian
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

    # sanic-praetorian config
    sanic_app.config.SECRET_KEY = "top secret"
    sanic_app.config["JWT_ACCESS_LIFESPAN"] = {"hours": 24}
    sanic_app.config["JWT_REFRESH_LIFESPAN"] = {"days": 30}

    # sanic-mailing config
    sanic_app.config.MAIL_SERVER = 'localhost:25'
    sanic_app.config.MAIL_USERNAME = ''
    sanic_app.config.MAIL_PASSWORD = ''
    sanic_app.config.MAIL_FROM = 'fake@fake.com'
    sanic_app.config.JWT_PLACES = ['header', 'cookie']

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
                          email="the_dude@praetorian.test.io",
                          password=_guard.hash_password("abides"),)

        await User.create(username="Walter",
                          email="walter@praetorian.test.io",
                          password=_guard.hash_password("calmerthanyouare"),
                          roles="admin",)

        await User.create(username="Donnie",
                          email="donnie@praetorian.test.io",
                          password=_guard.hash_password("iamthewalrus"),
                          roles="operator",)

        await User.create(username="Maude",
                          password=_guard.hash_password("andthorough"),
                          email="maude@praetorian.test.io",
                          roles="operator,admin",)

    # Set up some routes for the example
    @sanic_app.route("/login", methods=["POST"])
    async def login(request):
        """
        Logs a user in by parsing a POST request containing user credentials and
        issuing a JWT token.
        .. example::
           $ curl http://localhost:8000/login -X POST \
             -d '{"username":"Walter","password":"calmerthanyouare"}'
        """
        req = request.json
        username = req.get("username", None)
        password = req.get("password", None)
        user = await _guard.authenticate(username, password)
        ret = {"access_token": await _guard.encode_jwt_token(user)}
        return json(ret, status=200)

    @sanic_app.route("/protected")
    @sanic_praetorian.auth_required
    async def protected(request):
        """
        A protected endpoint. The auth_required decorator will require a header
        containing a valid JWT
        .. example::
           $ curl http://localhost:8000/protected -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_praetorian.current_user()
        return json({"message": f"protected endpoint (allowed user {user.username})"})

    @sanic_app.route("/protected_admin_required")
    @sanic_praetorian.roles_required("admin")
    async def protected_admin_required(request):
        """
        A protected endpoint that requires a role. The roles_required decorator
        will require that the supplied JWT includes the required roles
        .. example::
           $ curl http://localhost:8000/protected_admin_required -X GET \
              -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_praetorian.current_user()
        return json({"message": f"protected_admin_required endpoint (allowed user {user.username})"})

    @sanic_app.route("/protected_operator_accepted")
    @sanic_praetorian.roles_accepted("operator", "admin")
    async def protected_operator_accepted(request):
        """
        A protected endpoint that accepts any of the listed roles. The
        roles_accepted decorator will require that the supplied JWT includes at
        least one of the accepted roles
        .. example::
           $ curl http://localhost/protected_operator_accepted -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_praetorian.current_user()
        return json({"message": f"protected_operator_accepted endpoint (allowed usr {user.username}"})

    return sanic_app


# Run the example
if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)