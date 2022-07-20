from sanic import Sanic, json

from bson.objectid import ObjectId

import sanic_praetorian
from sanic_praetorian import Praetorian
from sanic_mailing import Mail

from umongo import Document, fields, validate
from umongo.exceptions import NotCreatedError

from umongo.frameworks.motor_asyncio import MotorAsyncIOInstance
from mongomock_motor import AsyncMongoMockClient


_guard = Praetorian()
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

    sanic_app.ctx.mail = _mail

    db = AsyncMongoMockClient()['test']
    instance = MotorAsyncIOInstance(db)
    instance.set_db(db)

    # A generic user model that might be used by an app powered by sanic-praetorian
    @instance.register
    class User(Document):
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

    _guard.init_app(sanic_app, User)

    # Add users for the example
    @sanic_app.listener('before_server_start')
    async def setup_example_db(sanic, loop):
        await User.ensure_indexes()

        await User(username="the_dude",
                   email="the_dude@praetorian.test.io",
                   password=_guard.hash_password("abides"),
        ).commit()

        await User(username="Walter",
                   email="walter@praetorian.test.io",
                   password=_guard.hash_password("calmerthanyouare"),
                   roles="admin",
        ).commit()

        await User(username="Donnie",
                   email="donnie@praetorian.test.io",
                   password=_guard.hash_password("iamthewalrus"),
                   roles="operator",
        ).commit()

        await User(username="Maude",
                   password=_guard.hash_password("andthorough"),
                   email="maude@praetorian.test.io",
                   roles="operator,admin",
        ).commit()


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