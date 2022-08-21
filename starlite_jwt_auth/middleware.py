from typing import TYPE_CHECKING

from starlette.requests import HTTPConnection
from starlette.types import ASGIApp
from starlite import AbstractAuthenticationMiddleware, AuthenticationResult

if TYPE_CHECKING:
    from starlite_jwt_auth.jwt_auth import JWTAuth


class JWTAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    def __init__(self, app: "ASGIApp", auth: "JWTAuth"):
        """This Class is a Starlite compatible JWT authentication middleware.

        It checks incoming requests for an encoded token in the auth header specified,
        and if present retrieves the user from persistence using the provided function.

        Args:
            app: An ASGIApp, this value is the next ASGI handler to call in the middleware stack.
            auth: The JWTAuth config instance.
        """
        super().__init__(app)
        self.auth = auth

    async def authenticate_request(self, request: HTTPConnection) -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header
        and retrieve the user correlating to the token from the DB.

        Args:
            request: An Starlette HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid or user is not found.
        """
        user, token = await self.auth.authenticate(connection=request)
        return AuthenticationResult(user=user, auth=token)
