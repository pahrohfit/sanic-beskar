from os import path as os_path
from sys import path as sys_path

sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

import sanic_beskar
from async_sender import Mail  # type: ignore
from sanic import Sanic, json
from sanic.log import logger
from sanic.views import HTTPMethodView
from sanic_beskar import Beskar
from sanic_beskar.exceptions import BeskarError
from tortoise.contrib.sanic import register_tortoise
from ujson import dumps as ujson_dumps
from ujson import loads as ujson_loads

from models import MixinUserTortoise

_guard = Beskar()
_mail = Mail()


def create_app(db_path=None):
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic("sanic-testing", dumps=ujson_dumps, loads=ujson_loads)
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.state.mode = "Mode.DEBUG"
    sanic_app.config.TESTING = True
    sanic_app.config["PYTESTING"] = True
    sanic_app.config.SECRET_KEY = "top secret 4nd comPLex radness!!"

    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    _guard.init_app(sanic_app, MixinUserTortoise)
    _guard.rbac_definitions = {
        "sooper_access_right": ["admin", "uber_admin"],
        "lame_access_right": ["not_admin"],
    }
    sanic_app.ctx.mail = _mail

    @sanic_app.route("/unprotected")
    def unprotected(request):
        """
        Endpoint without any security decorators
        """
        return json({"message": "success"})

    @sanic_app.route("/kinda_protected")
    @sanic_beskar.auth_accepted
    async def kinda_protected(request):
        """
        Endpoint that allows an authentication header (to set a user)
        """
        try:
            authed_user = await sanic_beskar.current_user()
            return json({"message": "success", "user": authed_user.username})
        except BeskarError:
            return json({"message": "success", "user": None})

    class ProtectedView(HTTPMethodView):
        @sanic_beskar.auth_required
        async def get(self, request):
            """
            Endpoint that requires an authentication header, via `class` based setup
            """
            return json({"message": "success"})

    sanic_app.add_route(ProtectedView.as_view(), "/protected_class")

    @sanic_app.route("/protected_route")
    @sanic_beskar.auth_required
    async def protected_route(request):
        """
        Endpoint requiring basic authentication header
        """
        return json({"message": "success"})

    @sanic_app.route("/rbac_protected")
    @sanic_beskar.auth_required
    @sanic_beskar.rights_required("sooper_access_right")
    async def rights_protected(request):
        """
        Endpoint looking for `sooper_access_right` RBAC rights
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_required")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_required("admin")
    async def protected_admin_required(request):
        """
        Endpoint requiring the user has an 'admin' role
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_required")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_required("admin", "operator")
    async def protected_admin_and_operator_required(request):
        """
        Endpoint requiring both 'admin' and 'operator' roles
        """
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_accepted")
    @sanic_beskar.auth_required
    @sanic_beskar.roles_accepted("admin", "operator")
    async def protected_admin_and_operator_accepted(request):
        """
        endpoint that requires 'admin' *and*/*or* 'operator' role
        """
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_required")
    @sanic_beskar.roles_required("admin")
    async def undecorated_admin_required(request):
        """
        Endpoint that doesn't use both decorators (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_accepted")
    @sanic_beskar.roles_accepted("admin")
    async def undecorated_admin_accepted(request):
        """
        Endpoint that doesn't use both decorators (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/reversed_decorators")
    @sanic_beskar.roles_required("admin", "operator")
    @sanic_beskar.auth_required
    async def reversed_decorators(request):
        """
        Endpoint with decorators in a different order (which is supported)
        """
        return json({"message": "success"})

    @sanic_app.route("/registration_confirmation")
    def reg_confirm(request):
        """
        Endpoint for registration testing
        """
        return json({"message": "fuck"})

    if not db_path:
        db_path = "sqlite://:memory:"
    logger.info(f"App db_path: {db_path}")
    register_tortoise(
        sanic_app,
        db_url=db_path,
        modules={"models": ["models"]},
        generate_schemas=True,
    )

    return sanic_app
