import re
from typing import TYPE_CHECKING, List, Optional, Pattern, Union

from starlite import (
    AbstractAuthenticationMiddleware,
    AuthenticationResult,
    NotAuthorizedException,
)
from starlite.utils import AsyncCallable

from starlite_jwt.token import Token

if TYPE_CHECKING:  # pragma: no cover
    from starlette.requests import HTTPConnection
    from starlette.types import ASGIApp, Receive, Scope, Send

    from starlite_jwt.types import RetrieveUserHandler


class JWTAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    def __init__(
        self,
        algorithm: str,
        app: "ASGIApp",
        auth_header: str,
        retrieve_user_handler: "RetrieveUserHandler",
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
        super().__init__(app)
        self.algorithm = algorithm
        self.auth_header = auth_header
        self.retrieve_user_handler = AsyncCallable(retrieve_user_handler)
        self.token_secret = token_secret

        self.exclude: Optional[Pattern[str]] = None
        if exclude:
            self.exclude = re.compile("|".join(exclude)) if isinstance(exclude, list) else re.compile(exclude)

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        """Override of the call method to allow skipping endpoints based on
        path regex matches.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.

        Returns:
            None
        """
        if self.exclude and self.exclude.findall(scope["path"]):
            await self.app(scope, receive, send)
        else:
            await super().__call__(scope, receive, send)

    async def authenticate_request(self, request: "HTTPConnection") -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header
        and retrieve the user correlating to the token from the DB.

        Args:
            request: An Starlette HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid or user is not found.
        """
        auth_header = request.headers.get(self.auth_header)
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
