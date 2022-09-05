from typing import TYPE_CHECKING, List, Optional, Union

from starlite import (
    AbstractAuthenticationMiddleware,
    AuthenticationResult,
    NotAuthorizedException,
)

from starlite_jwt.token import Token

if TYPE_CHECKING:  # pragma: no cover
    from typing import Any, Awaitable, Callable

    from starlette.requests import HTTPConnection
    from starlette.types import ASGIApp


class JWTAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    def __init__(
        self,
        algorithm: str,
        app: "ASGIApp",
        auth_header: str,
        retrieve_user_handler: "Callable[[str], Awaitable[Any]]",
        token_secret: str,
        exclude: Optional[Union[str, List[str]]],
    ):
        """This Class is a Starlite compatible JWT authentication middleware.

        It checks incoming requests for an encoded token in the auth header specified,
        and if present retrieves the user from persistence using the provided function.

        Args:
            app: An ASGIApp, this value is the next ASGI handler to call in the middleware stack.
            retrieve_user_handler: A function that receives an instance of 'Token' and returns a user, which can be
                any arbitrary value.
            token_secret: Secret for decoding the JWT token. This value should be equivalent to the secret used to encode it.
            auth_header: Request header key from which to retrieve the token. E.g. 'Authorization' or 'X-Api-Key'.
            algorithm: JWT hashing algorithm to use.
            exclude: A pattern or list of patterns to skip.
        """
        super().__init__(app=app, exclude=exclude)
        self.algorithm = algorithm
        self.auth_header = auth_header
        self.retrieve_user_handler = retrieve_user_handler
        self.token_secret = token_secret

    async def authenticate_request(self, connection: "HTTPConnection") -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header
        and retrieve the user correlating to the token from the DB.

        Args:
            connection: An Starlette HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid or user is not found.
        """
        auth_header = connection.headers.get(self.auth_header)
        if not auth_header:
            raise NotAuthorizedException("No JWT token found in request header")

        token = Token.decode(
            encoded_token=auth_header,
            secret=self.token_secret,
            algorithm=self.algorithm,
        )
        user = await self.retrieve_user_handler(token.sub)

        if not user:
            raise NotAuthorizedException()

        return AuthenticationResult(user=user, auth=token)
