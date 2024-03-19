import textwrap
import warnings

import pendulum
import plummet  # type: ignore
from httpx import Cookies
from sanic_beskar import Beskar
from sanic_beskar.exceptions import MissingRightError, MissingRoleError


class TestBeskarDecorators:
    """
    Unit tests against the included route decorators
    """

    async def test_verify_password(self, app, user_class, default_guard):
        """
        test_verify_password

        This test verifies that the _verify_password function can be used to
        successfully compare a raw password against its hashed version
        """
        secret = default_guard.hash_password("some password")
        assert default_guard._verify_password("some password", secret)
        assert not default_guard._verify_password("not right", secret)

        app.config["BESKAR_HASH_SCHEME"] = "pbkdf2_sha512"
        specified_guard = Beskar(app, user_class)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            specified_guard.pwd_ctx.update(pbkdf2_sha512__default_rounds=1)
        secret = specified_guard.hash_password("some password")
        assert specified_guard._verify_password("some password", secret)
        assert not specified_guard._verify_password("not right", secret)

    async def test_auth_accepted(self, default_guard, mock_users, client, app, user_class):
        """
        test_auth_accepted

        This test verifies that the @auth_accepted decorator can be used
        to optionally use a properly structured auth header including
        a valid token, setting the `current_user()`.
        """

        the_dude = await mock_users(username="the_dude")
        # Token is not in header or cookie
        _, response = await client.get(
            "/kinda_protected",
            headers={},
        )
        assert response.status == 200
        assert "success" in response.json["message"]
        assert response.json["user"] is None

        # Token is present and valid
        with plummet.frozen_time("2017-05-24 10:38:45"):
            _, response = await client.get(
                "/kinda_protected",
                headers=await default_guard.pack_header_for_user(the_dude),
            )
            assert response.status == 200
            assert "success" in response.json["message"]
            assert response.json["user"] == the_dude.username
        await the_dude.delete()

    async def test_auth_required(self, default_guard, mock_users, client):
        """
        test_auth_required

        This test verifies that the @auth_required decorator can be used
        to ensure that any access to a protected endpoint must have a properly
        structured auth header or cookie including a valid token.
        Otherwise, a 401 error occurs with an informative error message.
        """

        the_dude = await mock_users(username="the_dude")

        for route_name in ["/protected_class", "/protected_route"]:
            # Token is not in header or cookie
            _, response = await client.get(
                route_name,
                headers={},
            )

            exc_msg = textwrap.dedent(
                f"""
                    Could not find token in any
                     of the given locations: {default_guard.token_places}
                    """
            ).replace("\n", "")

            assert exc_msg in response.json["message"]
            assert response.status == 401

            # Token has invalid structure
            _, response = await client.get(
                route_name,
                headers={"Authorization": "bad_structure iamatoken"},
            )
            assert "Token header structure is invalid" in response.json["message"]
            assert response.status == 401

            # Token is expired
            moment = pendulum.parse("2017-05-24 10:18:45")
            with plummet.frozen_time(moment):
                headers = await default_guard.pack_header_for_user(the_dude)
            moment = moment + default_guard.access_lifespan + pendulum.Duration(seconds=1)
            with plummet.frozen_time(moment):
                _, response = await client.get(
                    route_name,
                    headers=headers,
                )
                assert response.status == 401
                assert "access permission has expired" in response.json["message"]

            # Token is present and valid in header or cookie
            with plummet.frozen_time("2017-05-24 10:38:45"):
                _, response = await client.get(
                    route_name,
                    headers=await default_guard.pack_header_for_user(the_dude),
                )

                assert response.status == 200

                cookies = Cookies()
                token = await default_guard.encode_token(the_dude)
                cookies[default_guard.cookie_name] = token
                _, response = await client.get(route_name, cookies=cookies)
                assert response.status == 200

    async def test_roles_required(self, default_guard, mock_users, client):
        """
        test_roles_required

        This test verifies that the @roles_required decorator can be used
        to ensure that any users attempting to access a given endpoint must
        have all of the roles listed. If the correct roles are not supplied,
        a 401 error occurs with an informative error message.  This
        test also verifies that the @roles_required can be used with or without
        an explicit @auth_required decorator
        """

        the_dude = await mock_users(username="the_dude")
        # Lacks one of one required roles
        _, response = await client.get(
            "/protected_admin_required",
            headers=await default_guard.pack_header_for_user(the_dude),
        )
        assert response.status == 403
        assert "This endpoint requires all the following roles" in response.json["message"]

        walter = await mock_users(username="walter", roles="admin")
        # Has one of one required roles
        _, response = await client.get(
            "/protected_admin_required",
            headers=await default_guard.pack_header_for_user(walter),
        )
        assert response.status == 200

        # Lacks one of two required roles
        _, response = await client.get(
            "/protected_admin_and_operator_required",
            headers=await default_guard.pack_header_for_user(walter),
        )
        assert response.status == 403
        assert MissingRoleError.__name__ in response.json["message"]
        assert "This endpoint requires all the following roles" in response.json["message"]

        maude = await mock_users(username="maude", roles="operator,admin")
        # Has two of two required roles
        _, response = await client.get(
            "/protected_admin_and_operator_required",
            headers=await default_guard.pack_header_for_user(maude),
        )
        assert response.status == 200

        _, response = await client.get(
            "/undecorated_admin_required",
            headers=await default_guard.pack_header_for_user(maude),
        )
        assert response.status == 200

        _, response = await client.get(
            "/undecorated_admin_accepted",
            headers=await default_guard.pack_header_for_user(maude),
        )
        assert response.status == 200

        _, response = await client.get(
            "/reversed_decorators",
            headers=await default_guard.pack_header_for_user(maude),
        )
        assert response.status == 200

    async def test_roles_accepted(self, default_guard, client, mock_users):
        """
        test_roles_accepted

        This test verifies that the @roles_accepted decorator can be used
        to ensure that any users attempting to access a given endpoint must
        have one of the roles listed. If one of the correct roles are not
        supplied, a 401 error occurs with an informative error message.
        """

        the_dude = await mock_users(username="the_dude")
        _, response = await client.get(
            "/protected_class",
            headers=await default_guard.pack_header_for_user(the_dude),
        )
        assert response.status == 200

        _, response = await client.get(
            "/protected_admin_and_operator_accepted",
            headers=await default_guard.pack_header_for_user(the_dude),
        )
        assert response.status == 403
        assert MissingRoleError.__name__ in response.json["message"]
        assert "This endpoint requires one of the following roles" in response.json["message"]

        walter = await mock_users(username="walter", roles="admin")
        _, response = await client.get(
            "/protected_admin_and_operator_accepted",
            headers=await default_guard.pack_header_for_user(walter),
        )
        assert response.status == 200

        donnie = await mock_users(username="donnie", roles="operator")
        _, response = await client.get(
            "/protected_admin_and_operator_accepted",
            headers=await default_guard.pack_header_for_user(donnie),
        )
        assert response.status == 200

        maude = await mock_users(username="maude", roles="operator,admin")
        _, response = await client.get(
            "/protected_admin_and_operator_accepted",
            headers=await default_guard.pack_header_for_user(maude),
        )
        assert response.status == 200

        jesus = await mock_users(username="jesus", roles="admin,god")
        _, response = await client.get(
            "/protected_admin_and_operator_accepted",
            headers=await default_guard.pack_header_for_user(jesus),
        )
        assert response.status == 200

    async def test_rights_required(self, client, mock_users, default_guard):
        """
        test_rights_required

        This test verifies that the @rights_required decorator can be used
        to ensure that any users attempting to access a given endpoint or
        resource must have all of the rights listed.  If a rights failure,
        a 401 error occurs with an informative error message.
        """
        from sanic.log import logger

        the_dude = await mock_users(username="the_dude", roles="admin")
        walter = await mock_users(username="walter", roles="not_admin")

        _, response = await client.get(
            "/rbac_protected",
            headers=await default_guard.pack_header_for_user(the_dude),
        )
        logger.critical(f"Response: {response.json}")
        assert response.status == 200

        _, response = await client.get(
            "/rbac_protected",
            headers=await default_guard.pack_header_for_user(walter),
        )
        assert response.status == 403
        assert MissingRightError.__name__ in response.json["message"]
        assert "This endpoint requires all the following rights" in response.json["message"]
