from sanic import Sanic, json

from bson.objectid import ObjectId

import sanic_beskar
from sanic_beskar import Beskar, UmongoUserMixin
from sanic_mailing import Mail

from umongo import Document, fields, validate
from umongo.exceptions import NotCreatedError

from umongo.frameworks.motor_asyncio import MotorAsyncIOInstance
from mongomock_motor import AsyncMongoMockClient


_guard = Beskar()
_mail = Mail()


def create_app(db_path=None):
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic('sanic-testing')
    sanic_app.config['PYTESTING'] = True
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    # sanic-beskar config
    sanic_app.config.SECRET_KEY = "top secret"
    sanic_app.config["TOKEN_ACCESS_LIFESPAN"] = {"hours": 24}
    sanic_app.config["TOKEN_REFRESH_LIFESPAN"] = {"days": 30}

    # sanic-mailing config
    sanic_app.config.MAIL_SERVER = 'localhost:25'
    sanic_app.config.MAIL_USERNAME = ''
    sanic_app.config.MAIL_PASSWORD = ''
    sanic_app.config.MAIL_FROM = 'fake@fake.com'
    sanic_app.config.TOKEN_PLACES = ['header', 'cookie']

    sanic_app.ctx.mail = _mail

    db = AsyncMongoMockClient()['test']
    instance = MotorAsyncIOInstance(db)
    instance.set_db(db)

    # A generic user model that might be used by an app powered by sanic-beskar
    @instance.register
    class User(UmongoUserMixin, Document):
        """
        Provides a basic user model for use in the tests
        """

        class Meta:
            table = "User"

        id = fields.ObjectIdField()
        username = fields.StringField(allow_none=False, unique=True, validate=[validate.Length(max=255)])
        password = fields.StringField(allow_none=False, validate=[validate.Length(max=255)])
        email = fields.StringField(unique=True, allow_none=False, validate=[validate.Length(max=128)])
        roles = fields.StringField(load_default='')
        is_active = fields.BooleanField(load_default=True)

        def __str__(self):
            return f"User {self.id}: {self.username}"

    _guard.init_app(sanic_app, User)

    # Add users for the example
    @sanic_app.listener('before_server_start')
    async def setup_example_db(sanic, loop):
        await User.ensure_indexes()

        await User(username="the_dude",
                   email="the_dude@beskart.io",
                   password=_guard.hash_password("abides"),
        ).commit()

        await User(username="Walter",
                   email="walter@beskar.test.io",
                   password=_guard.hash_password("calmerthanyouare"),
                   roles="admin",
        ).commit()

        await User(username="Donnie",
                   email="donnie@beskar.test.io",
                   password=_guard.hash_password("iamthewalrus"),
                   roles="operator",
        ).commit()

        await User(username="Maude",
                   password=_guard.hash_password("andthorough"),
                   email="maude@beskar.test.io",
                   roles="operator,admin",
        ).commit()


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
